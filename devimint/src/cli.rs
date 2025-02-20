use std::fmt::Write;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{env, ffi};

use anyhow::{anyhow, ensure, Context, Result};
use clap::{Parser, Subcommand};
use fedimint_core::task::TaskGroup;
use fedimint_core::util::{write_overwrite_async, FmtCompactAnyhow as _};
use fedimint_logging::LOG_DEVIMINT;
use rand::distributions::Alphanumeric;
use rand::Rng as _;
use tokio::fs;
use tokio::net::TcpStream;
use tokio::time::Instant;
use tracing::{debug, error, info, trace, warn};

use crate::devfed::DevJitFed;
use crate::envs::{
    FM_DEVIMINT_STATIC_DATA_DIR_ENV, FM_FED_SIZE_ENV, FM_INVITE_CODE_ENV, FM_LINK_TEST_DIR_ENV,
    FM_OFFLINE_NODES_ENV, FM_TEST_DIR_ENV,
};
use crate::federation::Fedimintd;
use crate::util::{poll, ProcessManager};
use crate::vars::mkdir;
use crate::{external_daemons, vars, ExternalDaemons};

fn random_test_dir_suffix() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .filter(u8::is_ascii_digit)
        .take(3)
        .map(char::from)
        .collect::<String>()
}

#[derive(Parser, Clone, Default)]
pub struct CommonArgs {
    #[clap(short = 'd', long, env = FM_TEST_DIR_ENV)]
    pub test_dir: Option<PathBuf>,

    /// Don't set up new Federation, start from the state in existing
    /// devimint data dir
    #[arg(long, env = "FM_SKIP_SETUP")]
    skip_setup: bool,

    #[clap(short = 'n', long, env = FM_FED_SIZE_ENV, default_value = "4")]
    pub fed_size: usize,

    #[clap(long, env = FM_LINK_TEST_DIR_ENV)]
    /// Create a link to the test dir under this path
    pub link_test_dir: Option<PathBuf>,

    #[clap(long, default_value_t = random_test_dir_suffix())]
    pub link_test_dir_suffix: String,

    /// Run degraded federation with FM_OFFLINE_NODES shutdown
    #[clap(long, env = FM_OFFLINE_NODES_ENV, default_value = "0")]
    pub offline_nodes: usize,
}

impl CommonArgs {
    pub fn mk_test_dir(&self) -> Result<PathBuf> {
        if self.skip_setup {
            ensure!(
                self.test_dir.is_some(),
                "When using `--skip-setup`, `--test-dir` must be set"
            );
        }
        let path = self.test_dir();

        std::fs::create_dir_all(&path)
            .with_context(|| format!("Creating tmp directory {}", path.display()))?;

        Ok(path)
    }

    pub fn test_dir(&self) -> PathBuf {
        self.test_dir.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!(
                "devimint-{}-{}",
                std::process::id(),
                self.link_test_dir_suffix
            ))
        })
    }
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Spins up bitcoind, cln, lnd, electrs, esplora, and opens a channel
    /// between the two lightning nodes
    ExternalDaemons {
        #[arg(long, trailing_var_arg = true, allow_hyphen_values = true, num_args=1..)]
        exec: Option<Vec<ffi::OsString>>,
    },
    /// Spins up bitcoind, cln, lnd w/ gateway, a faucet, electrs,
    /// esplora, and a federation sized from FM_FED_SIZE it opens LN channel
    /// between the two nodes. it connects the gateways to the federation.
    /// it finally switches to use the LND gateway for LNv1
    DevFed {
        #[arg(long, trailing_var_arg = true, allow_hyphen_values = true, num_args=1..)]
        exec: Option<Vec<ffi::OsString>>,
    },
    /// Runs bitcoind, spins up FM_FED_SIZE worth of fedimints
    RunUi,
    /// Rpc commands to the long running devimint instance. Could be entry point
    /// for devimint as a cli
    #[clap(flatten)]
    Rpc(RpcCmd),
}

#[derive(Subcommand)]
pub enum RpcCmd {
    Wait,
    Env,
}

pub async fn setup(arg: CommonArgs) -> Result<(ProcessManager, TaskGroup)> {
    let test_dir = &arg.mk_test_dir()?;
    mkdir(test_dir.clone()).await?;
    let logs_dir: PathBuf = test_dir.join("logs");
    mkdir(logs_dir.clone()).await?;

    let log_file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(logs_dir.join("devimint.log"))
        .await?
        .into_std()
        .await;

    fedimint_logging::TracingSetup::default()
        .with_file(Some(log_file))
        // jsonrpsee is expected to fail during startup
        .with_directive("jsonrpsee-client=off")
        .init()?;

    let globals = vars::Global::new(test_dir, arg.fed_size, arg.offline_nodes).await?;

    if let Some(link_test_dir) = arg.link_test_dir.as_ref() {
        update_test_dir_link(link_test_dir, &arg.test_dir()).await?;
    }
    info!(target: LOG_DEVIMINT, path=%globals.FM_DATA_DIR.display() , "Devimint data dir");

    let mut env_string = String::new();
    for (var, value) in globals.vars() {
        debug!(var, value, "Env variable set");
        writeln!(env_string, r#"export {var}="{value}""#)?; // hope that value doesn't contain a "
        std::env::set_var(var, value);
    }
    write_overwrite_async(globals.FM_TEST_DIR.join("env"), env_string).await?;
    let process_mgr = ProcessManager::new(globals);
    let task_group = TaskGroup::new();
    task_group.install_kill_handler();
    Ok((process_mgr, task_group))
}

pub async fn update_test_dir_link(
    link_test_dir: &Path,
    test_dir: &Path,
) -> Result<(), anyhow::Error> {
    let make_link = if let Ok(existing) = fs::read_link(link_test_dir).await {
        if existing == test_dir {
            false
        } else {
            debug!(
                old = %existing.display(),
                new = %test_dir.display(),
                link = %link_test_dir.display(),
                "Updating exinst test dir link"
            );

            fs::remove_file(link_test_dir).await?;
            true
        }
    } else {
        true
    };
    if make_link {
        debug!(src = %test_dir.display(), dst = %link_test_dir.display(), "Linking test dir");
        fs::symlink(&test_dir, link_test_dir).await?;
    }
    Ok(())
}

pub async fn cleanup_on_exit<T>(
    main_process: impl futures::Future<Output = Result<T>>,
    task_group: TaskGroup,
) -> Result<Option<T>> {
    match task_group
        .make_handle()
        .cancel_on_shutdown(main_process)
        .await
    {
        Err(_) => {
            info!("Received shutdown signal before finishing main process, exiting early");
            Ok(None)
        }
        Ok(Ok(v)) => {
            debug!(target: LOG_DEVIMINT, "Main process finished successfully, shutting down task group");
            task_group
                .shutdown_join_all(Duration::from_secs(30))
                .await?;

            // the caller can drop the v after shutdown
            Ok(Some(v))
        }
        Ok(Err(err)) => {
            warn!(target: LOG_DEVIMINT, err = %err.fmt_compact_anyhow(), "Main process failed, will shutdown");
            Err(err)
        }
    }
}

pub async fn write_ready_file<T>(global: &vars::Global, result: Result<T>) -> Result<T> {
    let ready_file = &global.FM_READY_FILE;
    match result {
        Ok(_) => write_overwrite_async(ready_file, "READY").await?,
        Err(_) => write_overwrite_async(ready_file, "ERROR").await?,
    }
    result
}

pub async fn handle_command(cmd: Cmd, common_args: CommonArgs) -> Result<()> {
    match cmd {
        Cmd::ExternalDaemons { exec } => {
            let (process_mgr, task_group) = setup(common_args).await?;
            let _daemons =
                write_ready_file(&process_mgr.globals, external_daemons(&process_mgr).await)
                    .await?;
            if let Some(exec) = exec {
                exec_user_command(exec).await?;
                task_group.shutdown();
            }
            task_group.make_handle().make_shutdown_rx().await;
        }
        Cmd::DevFed { exec } => {
            trace!(target: LOG_DEVIMINT, "Starting dev fed");
            let start_time = Instant::now();
            let skip_setup = common_args.skip_setup;
            let (process_mgr, task_group) = setup(common_args).await?;
            let main = {
                let task_group = task_group.clone();
                async move {
                    let dev_fed = DevJitFed::new(&process_mgr, skip_setup)?;

                    let pegin_start_time = Instant::now();
                    debug!(target: LOG_DEVIMINT, "Peging in client and gateways");

                    if !skip_setup {
                        const GW_PEGIN_AMOUNT: u64 = 1_000_000;
                        const CLIENT_PEGIN_AMOUNT: u64 = 1_000_000;

                        let (operation_id, (), ()) = tokio::try_join!(
                            async {
                                let (address, operation_id) =
                                    dev_fed.internal_client().await?.get_deposit_addr().await?;
                                dev_fed
                                    .bitcoind()
                                    .await?
                                    .send_to(address, CLIENT_PEGIN_AMOUNT)
                                    .await?;
                                Ok(operation_id)
                            },
                            async {
                                let pegin_addr = dev_fed
                                    .gw_lnd_registered()
                                    .await?
                                    .get_pegin_addr(&dev_fed.fed().await?.calculate_federation_id())
                                    .await?;
                                dev_fed
                                    .bitcoind()
                                    .await?
                                    .send_to(pegin_addr, GW_PEGIN_AMOUNT)
                                    .await
                                    .map(|_| ())
                            },
                            async {
                                if let Some(gw_ldk) = dev_fed.gw_ldk_connected().await? {
                                    let pegin_addr = gw_ldk
                                        .get_pegin_addr(
                                            &dev_fed.fed().await?.calculate_federation_id(),
                                        )
                                        .await?;
                                    dev_fed
                                        .bitcoind()
                                        .await?
                                        .send_to(pegin_addr, GW_PEGIN_AMOUNT)
                                        .await
                                        .map(|_| ())
                                } else {
                                    Ok(())
                                }
                            },
                        )?;

                        dev_fed.bitcoind().await?.mine_blocks_no_wait(11).await?;
                        dev_fed
                            .internal_client()
                            .await?
                            .await_deposit(&operation_id)
                            .await?;

                        info!(target: LOG_DEVIMINT,
                        elapsed_ms = %pegin_start_time.elapsed().as_millis(),
                        "Pegins completed");
                    }

                    std::env::set_var(FM_INVITE_CODE_ENV, dev_fed.fed().await?.invite_code()?);

                    dev_fed.finalize(&process_mgr).await?;

                    let daemons = write_ready_file(&process_mgr.globals, Ok(dev_fed)).await?;

                    info!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed().as_millis(), "Devfed ready");
                    if let Some(exec) = exec {
                        debug!(target: LOG_DEVIMINT, "Starting exec command");
                        exec_user_command(exec).await?;
                        task_group.shutdown();
                    }

                    debug!(target: LOG_DEVIMINT, "Waiting for group task shutdown");
                    task_group.make_handle().make_shutdown_rx().await;

                    Ok::<_, anyhow::Error>(daemons)
                }
            };
            if let Some(fed) = cleanup_on_exit(main, task_group).await? {
                fed.fast_terminate().await;
            }
        }
        Cmd::Rpc(rpc_cmd) => rpc_command(rpc_cmd, common_args).await?,
        Cmd::RunUi => {
            let (process_mgr, task_group) = setup(common_args).await?;
            let task_group_clone = task_group.clone();
            let main = async {
                let result = run_ui(&process_mgr).await;
                let daemons = write_ready_file(&process_mgr.globals, result).await?;

                debug!(target: LOG_DEVIMINT, "Waiting for group task shutdown");
                task_group_clone.make_handle().make_shutdown_rx().await;

                Ok::<_, anyhow::Error>(daemons)
            };
            Box::pin(cleanup_on_exit(main, task_group)).await?;
        }
    }
    Ok(())
}

pub async fn exec_user_command(path: Vec<ffi::OsString>) -> Result<(), anyhow::Error> {
    let cmd_str = path
        .join(ffi::OsStr::new(" "))
        .to_string_lossy()
        .to_string();

    let path_with_aliases = if let Some(existing_path) = env::var_os("PATH") {
        let mut path = devimint_static_data_dir();
        path.push("/aliases:");
        path.push(existing_path);
        path
    } else {
        let mut path = devimint_static_data_dir();
        path.push("/aliases");
        path
    };
    debug!(target: LOG_DEVIMINT, cmd = %cmd_str, "Executing user command");
    if !tokio::process::Command::new(&path[0])
        .args(&path[1..])
        .env("PATH", path_with_aliases)
        .kill_on_drop(true)
        .status()
        .await
        .with_context(|| format!("Executing user command failed: {cmd_str}"))?
        .success()
    {
        error!(cmd = %cmd_str, "User command failed");
        return Err(anyhow!("User command failed: {cmd_str}"));
    }
    Ok(())
}

fn devimint_static_data_dir() -> ffi::OsString {
    // If set, use the runtime, otherwise the compile time value
    env::var_os(FM_DEVIMINT_STATIC_DATA_DIR_ENV).unwrap_or(
        env!(
            // Note: consant expression, not allowed, so we can't use the constant :/
            "FM_DEVIMINT_STATIC_DATA_DIR"
        )
        .into(),
    )
}

pub async fn rpc_command(rpc: RpcCmd, common: CommonArgs) -> Result<()> {
    fedimint_logging::TracingSetup::default().init()?;
    match rpc {
        RpcCmd::Env => {
            let env_file = common.test_dir().join("env");
            poll("env file", || async {
                if fs::try_exists(&env_file)
                    .await
                    .context("env file")
                    .map_err(ControlFlow::Continue)?
                {
                    Ok(())
                } else {
                    Err(ControlFlow::Continue(anyhow!("env file not found")))
                }
            })
            .await?;
            let env = fs::read_to_string(&env_file).await?;
            print!("{env}");
            Ok(())
        }
        RpcCmd::Wait => {
            let ready_file = common.test_dir().join("ready");
            poll("ready file", || async {
                if fs::try_exists(&ready_file)
                    .await
                    .context("ready file")
                    .map_err(ControlFlow::Continue)?
                {
                    Ok(())
                } else {
                    Err(ControlFlow::Continue(anyhow!("ready file not found")))
                }
            })
            .await?;
            let env = fs::read_to_string(&ready_file).await?;
            print!("{env}");

            // Append invite code to devimint env
            let test_dir = &common.test_dir();
            let env_file = test_dir.join("env");
            let invite_file = test_dir.join("cfg/invite-code");
            if fs::try_exists(&env_file).await.ok().unwrap_or(false)
                && fs::try_exists(&invite_file).await.ok().unwrap_or(false)
            {
                let invite = fs::read_to_string(&invite_file).await?;
                let mut env_string = fs::read_to_string(&env_file).await?;
                writeln!(env_string, r#"export FM_INVITE_CODE="{invite}""#)?;
                std::env::set_var(FM_INVITE_CODE_ENV, invite);
                write_overwrite_async(env_file, env_string).await?;
            }

            Ok(())
        }
    }
}

async fn run_ui(process_mgr: &ProcessManager) -> Result<(Vec<Fedimintd>, ExternalDaemons)> {
    let externals = external_daemons(process_mgr).await?;
    let fed_size = process_mgr.globals.FM_FED_SIZE;
    let fedimintds = futures::future::try_join_all((0..fed_size).map(|peer| {
        let bitcoind = externals.bitcoind.clone();
        async move {
            let peer_port = 10000 + 8137 + peer * 2;
            let api_port = peer_port + 1;
            let metrics_port = 3510 + peer;

            let vars = vars::Fedimintd {
                FM_BIND_P2P: format!("127.0.0.1:{peer_port}"),
                FM_P2P_URL: format!("fedimint://127.0.0.1:{peer_port}"),
                FM_BIND_API: format!("127.0.0.1:{api_port}"),
                FM_API_URL: format!("ws://127.0.0.1:{api_port}"),
                FM_DATA_DIR: process_mgr
                    .globals
                    .FM_DATA_DIR
                    .join(format!("fedimintd-{peer}")),
                FM_BIND_METRICS_API: format!("127.0.0.1:{metrics_port}"),
                FM_FORCE_BITCOIN_RPC_URL: format!(
                    "http://bitcoin:bitcoin@127.0.0.1:{}",
                    process_mgr.globals.FM_PORT_BTC_RPC
                ),
                FM_FORCE_BITCOIN_RPC_KIND: "bitcoind".into(),
            };
            let fm = Fedimintd::new(
                process_mgr,
                bitcoind.clone(),
                peer,
                &vars,
                "default".to_string(),
            )
            .await?;
            let server_addr = &vars.FM_BIND_API;

            poll("waiting for api startup", || async {
                TcpStream::connect(server_addr)
                    .await
                    .context("connect to api")
                    .map_err(ControlFlow::Continue)
            })
            .await?;

            anyhow::Ok(fm)
        }
    }))
    .await?;

    Ok((fedimintds, externals))
}
