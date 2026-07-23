use std::fmt::Write;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{env, ffi};

use anyhow::{Context, Result, anyhow, ensure};
use clap::builder::BoolishValueParser;
use clap::{Parser, Subcommand};
use fedimint_core::task::TaskGroup;
use fedimint_core::util::{FmtCompactAnyhow as _, write_overwrite_async};
use fedimint_logging::LOG_DEVIMINT;
use rand::Rng as _;
use rand::distributions::Alphanumeric;
use tokio::fs;
use tokio::time::Instant;
use tracing::{debug, error, info, trace, warn};

use crate::devfed::DevJitFed;
use crate::envs::{
    FM_DEVIMINT_STATIC_DATA_DIR_ENV, FM_FED_SIZE_ENV, FM_FEDERATIONS_BASE_PORT_ENV,
    FM_GATEWAY_BASE_PORT_ENV, FM_INVITE_CODE_ENV, FM_LINK_TEST_DIR_ENV, FM_NUM_FEDS_ENV,
    FM_OFFLINE_NODES_ENV, FM_PRE_DKG_ENV, FM_TEST_DIR_ENV,
};
use crate::util::{ProcessManager, poll};
use crate::vars::mkdir;
use crate::{external_daemons, vars};

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
    #[arg(long, env = "FM_SKIP_SETUP", value_parser = BoolishValueParser::new())]
    skip_setup: bool,

    /// Do not set up federation and stop at a pre-dkg stage
    #[arg(long, env = FM_PRE_DKG_ENV, value_parser = BoolishValueParser::new())]
    pre_dkg: bool,

    /// Number of peers to allocate in every federation
    #[clap(short = 'n', long, env = FM_FED_SIZE_ENV, default_value = "4")]
    pub fed_size: usize,

    /// Number of federations to allocate for the test/run
    #[clap(long, env = FM_NUM_FEDS_ENV, default_value = "1")]
    pub num_feds: usize,

    #[clap(long, env = FM_LINK_TEST_DIR_ENV)]
    /// Create a link to the test dir under this path
    pub link_test_dir: Option<PathBuf>,

    #[clap(long, default_value_t = random_test_dir_suffix())]
    pub link_test_dir_suffix: String,

    /// Run degraded federation with FM_OFFLINE_NODES shutdown
    #[clap(long, env = FM_OFFLINE_NODES_ENV, default_value = "0")]
    pub offline_nodes: usize,

    /// Force a base federations port, e.g. for convenience during dev tasks
    #[clap(long, env = FM_FEDERATIONS_BASE_PORT_ENV)]
    pub federations_base_port: Option<u16>,

    /// Force a base gateway port, e.g. for convenience during dev tasks
    #[clap(long, env = FM_GATEWAY_BASE_PORT_ENV)]
    pub gateway_base_port: Option<u16>,
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
    /// Spins up bitcoind and esplora.
    ExternalDaemons {
        #[arg(long, trailing_var_arg = true, allow_hyphen_values = true, num_args=1..)]
        exec: Option<Vec<ffi::OsString>>,
    },
    /// Spins up bitcoind, LDK Gateway, lnd w/ gateway, a faucet,
    /// esplora, and a federation sized from FM_FED_SIZE it opens LN channel
    /// between the two nodes. it connects the gateways to the federation.
    /// it finally switches to use the LND gateway for LNv1
    DevFed {
        #[arg(long, trailing_var_arg = true, allow_hyphen_values = true, num_args=1..)]
        exec: Option<Vec<ffi::OsString>>,
    },
    /// Spins up a dev federation, backs up fedimint-0, wipes it, and restarts
    /// it in setup mode for manual guardian restore UI testing.
    DevFedPreRestore {
        #[arg(long, trailing_var_arg = true, allow_hyphen_values = true, num_args=1..)]
        exec: Option<Vec<ffi::OsString>>,
    },
    /// Rpc commands to the long running devimint instance. Could be entry point
    /// for devimint as a cli
    #[clap(flatten)]
    Rpc(RpcCmd),
}

#[derive(Subcommand)]
pub enum RpcCmd {
    Wait,
    Env,
    /// Send SIGTERM to a named daemon using its PID file.
    Kill {
        /// Process name, e.g. "fedimintd-default-0", "bitcoind", "gatewayd-lnd"
        name: String,
    },
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

    let globals = vars::Global::new(
        test_dir,
        arg.num_feds,
        arg.fed_size,
        arg.offline_nodes,
        arg.federations_base_port,
        arg.gateway_base_port,
    )
    .await?;

    if let Some(link_test_dir) = arg.link_test_dir.as_ref() {
        update_test_dir_link(link_test_dir, &arg.test_dir()).await?;
    }
    info!(target: LOG_DEVIMINT, path = %globals.FM_DATA_DIR.display(), "Devimint data dir");

    let mut env_string = String::new();
    for (var, value) in globals.vars() {
        debug!(var, value, "Env variable set");
        writeln!(env_string, r#"export {var}="{value}""#)?; // hope that value doesn't contain a "
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var(var, value) };
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
    let make_link = match fs::read_link(link_test_dir).await {
        Ok(existing) => {
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
        }
        _ => true,
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
        Cmd::DevFed { exec } => handle_dev_fed_command(common_args, exec, false).await?,
        Cmd::DevFedPreRestore { exec } => handle_dev_fed_command(common_args, exec, true).await?,
        Cmd::Rpc(rpc_cmd) => rpc_command(rpc_cmd, common_args).await?,
    }
    Ok(())
}

async fn handle_dev_fed_command(
    common_args: CommonArgs,
    exec: Option<Vec<ffi::OsString>>,
    pre_restore: bool,
) -> Result<()> {
    trace!(target: LOG_DEVIMINT, "Starting dev fed");
    let start_time = Instant::now();
    let skip_setup = common_args.skip_setup;
    let pre_dkg = common_args.pre_dkg;
    ensure!(
        !pre_restore || (!skip_setup && !pre_dkg),
        "dev-fed-pre-restore cannot be combined with skip-setup or pre-dkg"
    );
    let (process_mgr, task_group) = setup(common_args).await?;
    let main = {
        let task_group = task_group.clone();
        async move {
            let dev_fed =
                DevJitFed::new_with_pre_restore(&process_mgr, skip_setup, pre_dkg, pre_restore)?;

            let pegin_start_time = Instant::now();
            debug!(target: LOG_DEVIMINT, "Peging in client and gateways");

            if !skip_setup && !pre_dkg && !pre_restore {
                const GW_PEGIN_AMOUNT: u64 = 1_000_000;
                const CLIENT_PEGIN_AMOUNT: u64 = 1_000_000;

                let (handle, (), ()) = tokio::try_join!(
                    async {
                        let (address, handle) =
                            dev_fed.internal_client().await?.get_deposit_addr().await?;
                        debug!(
                            target: LOG_DEVIMINT,
                            %address,
                            %handle,
                            "Sending funds to client deposit addr"
                        );
                        dev_fed
                            .bitcoind()
                            .await?
                            .send_to(address, CLIENT_PEGIN_AMOUNT)
                            .await?;
                        Ok(handle)
                    },
                    async {
                        let address = dev_fed
                            .gw_lnd_registered()
                            .await?
                            .client()
                            .get_pegin_addr(&dev_fed.fed().await?.calculate_federation_id())
                            .await?;
                        debug!(
                            target: LOG_DEVIMINT,
                            %address,
                            "Sending funds to LND deposit addr"
                        );
                        dev_fed
                            .bitcoind()
                            .await?
                            .send_to(address, GW_PEGIN_AMOUNT)
                            .await
                            .map(|_| ())
                    },
                    async {
                        if crate::util::supports_lnv2() {
                            let gw_ldk = dev_fed.gw_ldk_connected().await?;
                            let address = gw_ldk
                                .client()
                                .get_pegin_addr(&dev_fed.fed().await?.calculate_federation_id())
                                .await?;
                            debug!(
                                target: LOG_DEVIMINT,
                                %address,
                                "Sending funds to LDK deposit addr"
                            );
                            dev_fed
                                .bitcoind()
                                .await?
                                .send_to(address, GW_PEGIN_AMOUNT)
                                .await
                                .map(|_| ())
                        } else {
                            Ok(())
                        }
                    },
                )?;

                dev_fed.bitcoind().await?.mine_blocks_no_wait(11).await?;
                if crate::util::supports_wallet_v2() {
                    if crate::util::FedimintCli::version_or_default().await
                        >= *crate::version_constants::VERSION_0_12_0_ALPHA
                    {
                        // `handle` is the event log position to wait from.
                        dev_fed
                            .internal_client()
                            .await?
                            .await_receive(&handle)
                            .await?;
                    } else {
                        // Legacy walletv2 (<= 0.11) auto-claims deposits;
                        // wait for the balance to reflect the pegin.
                        dev_fed
                            .internal_client()
                            .await?
                            .await_balance(CLIENT_PEGIN_AMOUNT * 1000 * 9 / 10)
                            .await?;
                    }
                } else {
                    dev_fed
                        .internal_client()
                        .await?
                        .await_deposit(&handle)
                        .await?;
                }

                info!(
                    target: LOG_DEVIMINT,
                    elapsed_ms = %pegin_start_time.elapsed().as_millis(),
                    "Pegins completed"
                );
            }

            if !pre_dkg && !pre_restore {
                // TODO: Audit that the environment access only happens in single-threaded
                // code.
                unsafe {
                    std::env::set_var(FM_INVITE_CODE_ENV, dev_fed.fed().await?.invite_code()?);
                };
            }

            if pre_restore {
                let _ = dev_fed.fed().await?;
            } else {
                dev_fed.finalize(&process_mgr).await?;
            }

            let daemons = write_ready_file(&process_mgr.globals, Ok(dev_fed)).await?;

            info!(
                target: LOG_DEVIMINT,
                elapsed_ms = %start_time.elapsed().as_millis(),
                path = %process_mgr.globals.FM_DATA_DIR.display(),
                "Devfed ready"
            );
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
            // Note: constant expression, not allowed, so we can't use the constant :/
            "FM_DEVIMINT_STATIC_DATA_DIR"
        )
        .into(),
    )
}

/// Whether the process currently running as `pid` still matches the given
/// expected basename and start time recorded when it was spawned.
///
/// A basename match alone isn't enough to tell apart different instances of
/// the same binary (e.g. several `fedimintd`s in one federation), so this
/// also compares start time — a PID recycled from a dead instance onto a
/// live one of the same binary would fail this check. `Ok(false)` covers
/// both "no such process" and "a different process reused this pid".
///
/// `Err` means the check itself failed (e.g. `ps` could not be run) —
/// callers must not treat that as "gone", or a tooling hiccup would orphan
/// a live daemon.
async fn pid_identity_matches(
    pid: i32,
    expected_basename: &str,
    expected_start_time: &str,
) -> Result<bool> {
    let Some(running_basename) = crate::util::running_program_basename(pid as u32).await? else {
        return Ok(false);
    };
    let Some(running_start_time) = crate::util::process_start_time(pid as u32).await? else {
        return Ok(false);
    };
    Ok(running_basename == expected_basename && running_start_time == expected_start_time)
}

/// Whether the process is a zombie: already dead, just not yet reaped by
/// its parent (the long-running devimint that spawned it).
async fn is_zombie(pid: i32) -> bool {
    let Ok(output) = tokio::process::Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .await
    else {
        return false;
    };
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .starts_with('Z')
}

/// Polls `pid` until it's gone — or is a zombie, which signals can never
/// change from here — or `timeout` elapses. Returns whether it exited.
///
/// Uses a flat interval rather than the shared `backoff_util::custom_backoff`
/// helper: that's built for retrying operations of unknown duration where
/// growing the delay avoids hammering a remote service, but here exit is
/// usually near-instant and we want fast, consistent detection of it, not an
/// escalating delay before the next check.
async fn wait_for_pid_exit(pid_t: nix::unistd::Pid, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while nix::sys::signal::kill(pid_t, None).is_ok() {
        // `kill(pid, 0)` succeeds for zombies: the daemon is dead, its
        // parent just hasn't reaped it yet, so don't keep waiting on it.
        if is_zombie(pid_t.as_raw()).await {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        fedimint_core::runtime::sleep(Duration::from_millis(100)).await;
    }
    true
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
                // TODO: Audit that the environment access only happens in single-threaded code.
                unsafe { std::env::set_var(FM_INVITE_CODE_ENV, invite) };
                write_overwrite_async(env_file, env_string).await?;
            }

            Ok(())
        }
        RpcCmd::Kill { name } => {
            let pid_file = common.test_dir().join("logs").join(format!("{name}.pid"));
            let pid_file_contents = fs::read_to_string(&pid_file)
                .await
                .with_context(|| format!("No PID file for '{name}' — is it running?"))?;
            let mut lines = pid_file_contents.lines();
            let pid: i32 = lines
                .next()
                .with_context(|| format!("Empty PID file for '{name}'"))?
                .trim()
                .parse()
                .with_context(|| format!("Invalid PID in file for '{name}'"))?;
            let expected_program = lines.next().unwrap_or_default();
            let expected_start_time = lines.next().unwrap_or_default();
            ensure!(
                !expected_program.is_empty() && !expected_start_time.is_empty(),
                "PID file for '{name}' doesn't record enough identity info to \
                 safely verify (stale or old-format file?) — refusing to guess. \
                 Remove it manually if you're sure it's safe."
            );
            let expected_basename = Path::new(expected_program).file_name().map_or_else(
                || expected_program.to_owned(),
                |s| s.to_string_lossy().into_owned(),
            );

            // A stale PID file (daemon already exited, PID recycled by the OS)
            // could otherwise cause us to signal an unrelated process, so
            // confirm the running process is still the very same instance we
            // spawned (basename + start time) before signaling it. If it's
            // gone (or the pid now belongs to something else), the daemon is
            // already dead: clean up the stale PID file and succeed, so
            // `kill` is idempotent.
            if !pid_identity_matches(pid, &expected_basename, expected_start_time).await? {
                let _ = fs::remove_file(&pid_file).await;
                println!("'{name}' (pid {pid}) is not running anymore; removed stale PID file");
                return Ok(());
            }

            let pid_t = nix::unistd::Pid::from_raw(pid);
            nix::sys::signal::kill(pid_t, nix::sys::signal::Signal::SIGTERM)
                .with_context(|| format!("Failed to send SIGTERM to '{name}' (pid {pid})"))?;

            // Wait for the process to actually exit, escalating to SIGKILL if
            // it doesn't within a grace period. Re-verify identity right
            // before the SIGKILL too: the original process may have already
            // exited during the wait, letting the OS hand `pid` to an
            // unrelated process in the meantime. Only remove the PID file
            // once exit is actually confirmed (or the pid is confirmed to no
            // longer be ours anyway) — otherwise a still-running daemon
            // (e.g. one stuck in uninterruptible I/O, immune to SIGKILL until
            // it unblocks) would silently become untracked.
            let mut exited = wait_for_pid_exit(pid_t, Duration::from_secs(5)).await;
            let mut sigkilled = false;
            if !exited {
                match pid_identity_matches(pid, &expected_basename, expected_start_time).await {
                    Ok(true) => {
                        sigkilled = true;
                        let _ = nix::sys::signal::kill(pid_t, nix::sys::signal::Signal::SIGKILL);
                        exited = wait_for_pid_exit(pid_t, Duration::from_secs(5)).await;
                    }
                    Ok(false) => {
                        warn!(
                            target: LOG_DEVIMINT,
                            %name, pid,
                            "pid no longer matches the expected process after the \
                             SIGTERM wait; not escalating to SIGKILL (likely \
                             already exited and the pid was reused)"
                        );
                        // Not our process either way, so the PID file is stale
                        // regardless of whether *something* is still running.
                        exited = true;
                    }
                    Err(err) => {
                        // Couldn't verify: don't SIGKILL what we can't
                        // identify, and keep the PID file so a live daemon
                        // isn't orphaned by a tooling failure.
                        warn!(
                            target: LOG_DEVIMINT,
                            %name, pid, err = %err.fmt_compact_anyhow(),
                            "could not re-verify process identity after the \
                             SIGTERM wait; not escalating to SIGKILL"
                        );
                    }
                }
            }

            if exited {
                let _ = fs::remove_file(&pid_file).await;
                if sigkilled {
                    println!(
                        "'{name}' (pid {pid}) didn't respond to SIGTERM within 5s; \
                         sent SIGKILL"
                    );
                } else {
                    println!("Sent SIGTERM to '{name}' (pid {pid})");
                }
            } else {
                let signals_sent = if sigkilled {
                    "SIGTERM and SIGKILL"
                } else {
                    "SIGTERM"
                };
                println!(
                    "Sent {signals_sent} to '{name}' (pid {pid}), but it still \
                     appears to be running — leaving its PID file in place so \
                     it isn't lost track of."
                );
            }
            Ok(())
        }
    }
}
