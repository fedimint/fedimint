use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::future::Future;
use std::ops::ControlFlow;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use std::{env, unreachable};

use anyhow::{anyhow, bail, format_err, Context, Result};
use fedimint_api_client::api::StatusResponse;
use fedimint_core::admin_client::{
    ConfigGenParamsRequest, ConfigGenParamsResponse, PeerServerParams,
};
use fedimint_core::config::ServerModuleConfigGenParamsRegistry;
use fedimint_core::envs::is_env_var_set;
use fedimint_core::module::ApiAuth;
use fedimint_core::task::{self, block_in_place, block_on};
use fedimint_core::time::now;
use fedimint_core::PeerId;
use fedimint_logging::LOG_DEVIMINT;
use semver::Version;
use serde::de::DeserializeOwned;
use tokio::fs::OpenOptions;
use tokio::process::Child;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::envs::{
    FM_BACKWARDS_COMPATIBILITY_TEST_ENV, FM_BITCOIND_BASE_EXECUTABLE_ENV,
    FM_BITCOIN_CLI_BASE_EXECUTABLE_ENV, FM_BTC_CLIENT_ENV, FM_DEVIMINT_CMD_INHERIT_STDERR_ENV,
    FM_ELECTRS_BASE_EXECUTABLE_ENV, FM_ESPLORA_BASE_EXECUTABLE_ENV, FM_FAUCET_BASE_EXECUTABLE_ENV,
    FM_FEDIMINTD_BASE_EXECUTABLE_ENV, FM_FEDIMINT_CLI_BASE_EXECUTABLE_ENV,
    FM_FEDIMINT_DBTOOL_BASE_EXECUTABLE_ENV, FM_GATEWAYD_BASE_EXECUTABLE_ENV,
    FM_GATEWAY_CLI_BASE_EXECUTABLE_ENV, FM_GATEWAY_CLN_EXTENSION_BASE_EXECUTABLE_ENV,
    FM_GWCLI_CLN_ENV, FM_GWCLI_LND_ENV, FM_LIGHTNINGD_BASE_EXECUTABLE_ENV,
    FM_LIGHTNING_CLI_BASE_EXECUTABLE_ENV, FM_LIGHTNING_CLI_ENV, FM_LNCLI_BASE_EXECUTABLE_ENV,
    FM_LNCLI_ENV, FM_LND_BASE_EXECUTABLE_ENV, FM_LOAD_TEST_TOOL_BASE_EXECUTABLE_ENV,
    FM_LOGS_DIR_ENV, FM_MINT_CLIENT_ENV, FM_RECOVERYTOOL_BASE_EXECUTABLE_ENV,
};
use crate::version_constants::VERSION_0_5_0_ALPHA;

// If a binary doesn't provide a clap version, default to the first stable
// release (v0.2.1)
const DEFAULT_VERSION: Version = Version::new(0, 2, 1);

pub fn parse_map(s: &str) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();

    if s.is_empty() {
        return Ok(map);
    }

    for pair in s.split(',') {
        let parts: Vec<&str> = pair.split('=').collect();
        if parts.len() == 2 {
            map.insert(parts[0].to_string(), parts[1].to_string());
        } else {
            return Err(format_err!("Invalid pair in map: {}", pair));
        }
    }
    Ok(map)
}

fn send_sigterm(child: &Child) {
    send_signal(child, nix::sys::signal::Signal::SIGTERM);
}

fn send_sigkill(child: &Child) {
    send_signal(child, nix::sys::signal::Signal::SIGKILL);
}

fn send_signal(child: &Child, signal: nix::sys::signal::Signal) {
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id().expect("pid should be present") as _),
        signal,
    );
}

/// Kills process when all references to ProcessHandle are dropped.
///
/// NOTE: drop order is significant make sure fields in struct are declared in
/// correct order it is generally clients, process handle, deps
#[derive(Debug, Clone)]
pub struct ProcessHandle(Arc<Mutex<ProcessHandleInner>>);

impl ProcessHandle {
    pub async fn terminate(&self) -> Result<()> {
        let mut inner = self.0.lock().await;
        inner.terminate().await?;
        Ok(())
    }
    pub async fn is_running(&self) -> bool {
        self.0.lock().await.child.is_some()
    }
}

#[derive(Debug)]
pub struct ProcessHandleInner {
    name: String,
    child: Option<Child>,
}

impl ProcessHandleInner {
    async fn terminate(&mut self) -> anyhow::Result<()> {
        if let Some(child) = self.child.as_mut() {
            debug!(
                target: LOG_DEVIMINT,
                name=%self.name,
                signal="SIGTERM",
                "sending signal to terminate child process"
            );

            send_sigterm(child);

            if (fedimint_core::runtime::timeout(Duration::from_secs(2), child.wait()).await)
                .is_err()
            {
                debug!(
                    target: LOG_DEVIMINT,
                    name=%self.name,
                    signal="SIGKILL",
                    "sending signal to terminate child process"
                );

                send_sigkill(child);

                match fedimint_core::runtime::timeout(Duration::from_secs(5), child.wait()).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(err)) => {
                        bail!("Failed to terminate child process {}: {}", self.name, err);
                    }
                    Err(_) => {
                        bail!("Failed to terminate child process {}: timeout", self.name);
                    }
                }
            }
        }
        // only drop the child handle if succeeded to terminate
        self.child.take();
        Ok(())
    }
}

impl Drop for ProcessHandleInner {
    fn drop(&mut self) {
        if self.child.is_none() {
            return;
        }

        block_in_place(|| {
            if let Err(err) = block_on(self.terminate()) {
                warn!(target: LOG_DEVIMINT,
                        name=%self.name,
                        %err,
                        "Error terminating process on drop");
            }
        });
    }
}

#[derive(Clone)]
pub struct ProcessManager {
    pub globals: super::vars::Global,
}

impl ProcessManager {
    pub fn new(globals: super::vars::Global) -> Self {
        Self { globals }
    }

    /// Logs to $FM_LOGS_DIR/{name}.{out,err}
    pub async fn spawn_daemon(&self, name: &str, mut cmd: Command) -> Result<ProcessHandle> {
        let logs_dir = env::var(FM_LOGS_DIR_ENV)?;
        let path = format!("{logs_dir}/{name}.log");
        let log = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .await?
            .into_std()
            .await;
        cmd.cmd.kill_on_drop(false); // we handle killing ourself
        cmd.cmd.stdout(log.try_clone()?);
        cmd.cmd.stderr(log);
        let child = cmd
            .cmd
            .spawn()
            .with_context(|| format!("Could not spawn: {name}"))?;
        let handle = ProcessHandle(Arc::new(Mutex::new(ProcessHandleInner {
            name: name.to_owned(),
            child: Some(child),
        })));
        Ok(handle)
    }
}

pub struct Command {
    pub cmd: tokio::process::Command,
    pub args_debug: Vec<String>,
}

impl Command {
    pub fn arg<T: ToString>(mut self, arg: &T) -> Self {
        let string = arg.to_string();
        self.cmd.arg(string.clone());
        self.args_debug.push(string);
        self
    }

    pub fn args<T: ToString>(mut self, args: impl IntoIterator<Item = T>) -> Self {
        for arg in args {
            self = self.arg(&arg);
        }
        self
    }

    pub fn env<K, V>(mut self, key: K, val: V) -> Self
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.cmd.env(key, val);
        self
    }

    pub fn envs<I, K, V>(mut self, env: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.cmd.envs(env);
        self
    }

    pub fn kill_on_drop(mut self, kill: bool) -> Self {
        self.cmd.kill_on_drop(kill);
        self
    }

    /// Run the command and get its output as json.
    pub async fn out_json(&mut self) -> Result<serde_json::Value> {
        Ok(serde_json::from_str(&self.out_string().await?)?)
    }

    fn command_debug(&self) -> String {
        self.args_debug
            .iter()
            .map(|x| x.replace(' ', "␣"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Run the command and get its output as string.
    pub async fn out_string(&mut self) -> Result<String> {
        let output = self
            .run_inner(true)
            .await
            .with_context(|| format!("command: {}", self.command_debug()))?;
        let output = String::from_utf8(output.stdout)?;
        Ok(output.trim().to_owned())
    }

    /// Returns the json error if the command has a non-zero exit code.
    pub async fn expect_err_json(&mut self) -> Result<serde_json::Value> {
        let output = self
            .run_inner(false)
            .await
            .with_context(|| format!("command: {}", self.command_debug()))?;
        let output = String::from_utf8(output.stdout)?;
        Ok(serde_json::from_str(output.trim())?)
    }

    /// Run the command expecting an error, which is parsed using a closure.
    /// Returns an Err if the closure returns false.
    pub async fn assert_error(
        &mut self,
        predicate: impl Fn(serde_json::Value) -> bool,
    ) -> Result<()> {
        let parsed_error = self.expect_err_json().await?;
        anyhow::ensure!(predicate(parsed_error));
        Ok(())
    }

    /// Returns an Err if the command doesn't return an error containing the
    /// provided error string.
    pub async fn assert_error_contains(&mut self, error: &str) -> Result<()> {
        self.assert_error(|err_json| {
            let error_string = err_json
                .get("error")
                .expect("json error contains error field")
                .as_str()
                .expect("not a string")
                .to_owned();

            error_string.contains(error)
        })
        .await
    }

    pub async fn run_inner(&mut self, expect_success: bool) -> Result<std::process::Output> {
        debug!(target: LOG_DEVIMINT, "> {}", self.command_debug());
        let output = self
            .cmd
            .stdout(Stdio::piped())
            .stderr(if is_env_var_set(FM_DEVIMINT_CMD_INHERIT_STDERR_ENV) {
                Stdio::inherit()
            } else {
                Stdio::piped()
            })
            .spawn()?
            .wait_with_output()
            .await?;

        if output.status.success() != expect_success {
            bail!(
                "{}\nstdout:\n{}\nstderr:\n{}\n",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        Ok(output)
    }

    /// Run the command ignoring its output.
    pub async fn run(&mut self) -> Result<()> {
        let _ = self
            .run_inner(true)
            .await
            .with_context(|| format!("command: {}", self.command_debug()))?;
        Ok(())
    }

    /// Run the command logging the output and error
    pub async fn run_with_logging(&mut self, name: String) -> Result<()> {
        let logs_dir = env::var(FM_LOGS_DIR_ENV)?;
        let path = format!("{logs_dir}/{name}.log");
        let log = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .await
            .with_context(|| format!("path: {path} cmd: {name}"))?
            .into_std()
            .await;
        self.cmd.stdout(log.try_clone()?);
        self.cmd.stderr(log);
        let status = self
            .cmd
            .spawn()
            .with_context(|| format!("cmd: {name}"))?
            .wait()
            .await?;
        if !status.success() {
            bail!("{}", status);
        }
        Ok(())
    }
}

/// easy syntax to create a Command
///
/// `(A1, A2, A3)` expands to
/// ```ignore
/// A1.cmd().await?
///     .arg(A2)
///     .arg(A3)
///     .kill_on_drop(true)
/// ```
///
/// If `An` is a string literal, it is replaced with `format!(a)`
#[macro_export]
macro_rules! cmd {
    ($(@head ($($head:tt)* ))? $curr:literal $(, $($tail:tt)*)?) => {
        cmd! {
            @head ($($($head)*)? format!($curr),)
            $($($tail)*)?
        }
    };
    ($(@head ($($head:tt)* ))? $curr:expr $(, $($tail:tt)*)?) => {
        cmd! {
            @head ($($($head)*)? $curr,)
            $($($tail)*)?
        }
    };
    (@head ($($head:tt)* )) => {
        cmd! {
            @last
            $($head)*
        }
    };
    // last matcher
    (@last $this:expr, $($arg:expr),* $(,)?) => {
        {
            #[allow(unused)]
            use $crate::util::ToCmdExt;
            $this.cmd()
                $(.arg(&$arg))*
                .kill_on_drop(true)
                .env("RUST_BACKTRACE", "1")
        }
    };
}

#[macro_export]
macro_rules! poll_eq {
    ($left:expr, $right:expr) => {
        match ($left, $right) {
            (left, right) => {
                if left == right {
                    Ok(())
                } else {
                    Err(std::ops::ControlFlow::Continue(anyhow::anyhow!(
                        "assertion failed, left: {left:?} right: {right:?}"
                    )))
                }
            }
        }
    };
}

// Allow macro to be used within the crate. See https://stackoverflow.com/a/31749071.
pub(crate) use cmd;

/// Retry until `f` succeeds or timeout is reached
///
/// - if `f` return Ok(val), this returns with Ok(val).
/// - if `f` return Err(Control::Break(err)), this returns Err(err)
/// - if `f` return Err(ControlFlow::Continue(err)), retries until timeout
///   reached
pub async fn poll_with_timeout<Fut, R>(
    name: &str,
    timeout: Duration,
    f: impl Fn() -> Fut,
) -> Result<R>
where
    Fut: Future<Output = Result<R, ControlFlow<anyhow::Error, anyhow::Error>>>,
{
    let start = now();
    for attempt in 0u64.. {
        let attempt_start = now();
        match f().await {
            Ok(value) => return Ok(value),
            Err(ControlFlow::Break(err)) => {
                return Err(err).with_context(|| format!("polling {name}"));
            }
            Err(ControlFlow::Continue(err))
                if attempt_start
                    .duration_since(start)
                    .expect("time goes forward")
                    < timeout =>
            {
                debug!(target: LOG_DEVIMINT, %attempt, %err, "Polling {name} failed, will retry...");
                task::sleep(Duration::from_millis((attempt * 10).min(1000))).await;
            }
            Err(ControlFlow::Continue(err)) => {
                return Err(err).with_context(|| {
                    format!(
                        "Polling {name} failed after {attempt} retries (timeout: {}s)",
                        timeout.as_secs()
                    )
                });
            }
        }
    }

    unreachable!();
}

const DEFAULT_POLL_TIMEOUT: Duration = Duration::from_secs(60);

/// Retry until `f` succeeds or default timeout is reached
///
/// - if `f` return Ok(val), this returns with Ok(val).
/// - if `f` return Err(Control::Break(err)), this returns Err(err)
/// - if `f` return Err(ControlFlow::Continue(err)), retries until timeout
///   reached
pub async fn poll<Fut, R>(name: &str, f: impl Fn() -> Fut) -> Result<R>
where
    Fut: Future<Output = Result<R, ControlFlow<anyhow::Error, anyhow::Error>>>,
{
    poll_with_timeout(name, DEFAULT_POLL_TIMEOUT, f).await
}

pub async fn poll_simple<Fut, R>(name: &str, f: impl Fn() -> Fut) -> Result<R>
where
    Fut: Future<Output = Result<R, anyhow::Error>>,
{
    let start = now();
    let timeout = DEFAULT_POLL_TIMEOUT;
    for attempt in 0u64.. {
        let attempt_start = now();
        match f().await {
            Ok(value) => return Ok(value),
            Err(err)
                if attempt_start
                    .duration_since(start)
                    .expect("time goes forward")
                    < timeout =>
            {
                debug!(target: LOG_DEVIMINT, %attempt, %err, "Polling {name} failed, will retry...");
                task::sleep(Duration::from_millis((attempt * 10).min(1000))).await;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "Polling {name} failed after {attempt} retries (timeout: {}s)",
                        timeout.as_secs()
                    )
                });
            }
        }
    }

    unreachable!();
}

// used to add `cmd` method.
pub trait ToCmdExt {
    fn cmd(self) -> Command;
}

// a command that uses self as program name
impl ToCmdExt for &'_ str {
    fn cmd(self) -> Command {
        Command {
            cmd: tokio::process::Command::new(self),
            args_debug: vec![self.to_owned()],
        }
    }
}

impl ToCmdExt for Vec<String> {
    fn cmd(self) -> Command {
        to_command(self)
    }
}

pub trait JsonValueExt {
    fn to_typed<T: DeserializeOwned>(self) -> Result<T>;
}

impl JsonValueExt for serde_json::Value {
    fn to_typed<T: DeserializeOwned>(self) -> Result<T> {
        Ok(serde_json::from_value(self)?)
    }
}

const GATEWAYD_FALLBACK: &str = "gatewayd";

const FEDIMINTD_FALLBACK: &str = "fedimintd";

const FEDIMINT_CLI_FALLBACK: &str = "fedimint-cli";

pub fn get_fedimint_cli_path() -> Vec<String> {
    get_command_str_for_alias(
        &[FM_FEDIMINT_CLI_BASE_EXECUTABLE_ENV],
        &[FEDIMINT_CLI_FALLBACK],
    )
}

const GATEWAY_CLI_FALLBACK: &str = "gateway-cli";

pub fn get_gateway_cli_path() -> Vec<String> {
    get_command_str_for_alias(
        &[FM_GATEWAY_CLI_BASE_EXECUTABLE_ENV],
        &[GATEWAY_CLI_FALLBACK],
    )
}

const GATEWAY_CLN_EXTENSION_FALLBACK: &str = "gateway-cln-extension";

pub fn get_gateway_cln_extension_path(default_path: &str) -> Vec<String> {
    get_command_str_for_alias(
        &[FM_GATEWAY_CLN_EXTENSION_BASE_EXECUTABLE_ENV],
        &[default_path],
    )
}

const LOAD_TEST_TOOL_FALLBACK: &str = "fedimint-load-test-tool";

const LIGHTNING_CLI_FALLBACK: &str = "lightning-cli";

pub fn get_lightning_cli_path() -> Vec<String> {
    get_command_str_for_alias(
        &[FM_LIGHTNING_CLI_BASE_EXECUTABLE_ENV],
        &[LIGHTNING_CLI_FALLBACK],
    )
}

const LNCLI_FALLBACK: &str = "lncli";

pub fn get_lncli_path() -> Vec<String> {
    get_command_str_for_alias(&[FM_LNCLI_BASE_EXECUTABLE_ENV], &[LNCLI_FALLBACK])
}

const BITCOIN_CLI_FALLBACK: &str = "bitcoin-cli";

pub fn get_bitcoin_cli_path() -> Vec<String> {
    get_command_str_for_alias(
        &[FM_BITCOIN_CLI_BASE_EXECUTABLE_ENV],
        &[BITCOIN_CLI_FALLBACK],
    )
}

const BITCOIND_FALLBACK: &str = "bitcoind";

const LIGHTNINGD_FALLBACK: &str = "lightningd";

const LND_FALLBACK: &str = "lnd";

const ELECTRS_FALLBACK: &str = "electrs";

const ESPLORA_FALLBACK: &str = "esplora";

const RECOVERYTOOL_FALLBACK: &str = "fedimint-recoverytool";

const FAUCET_FALLBACK: &str = "faucet";

const FEDIMINT_DBTOOL_FALLBACK: &str = "fedimint-dbtool";

pub fn get_fedimint_dbtool_cli_path() -> Vec<String> {
    get_command_str_for_alias(
        &[FM_FEDIMINT_DBTOOL_BASE_EXECUTABLE_ENV],
        &[FEDIMINT_DBTOOL_FALLBACK],
    )
}

/// Maps a version hash to a release version
fn version_hash_to_version(version_hash: &str) -> Result<Version> {
    match version_hash {
        "a8422b84102ab5fc768307215d5b20d807143f27" => Ok(Version::new(0, 2, 1)),
        "a849377f6466b26bf9b2747242ff01fd4d4a031b" => Ok(Version::new(0, 2, 2)),
        _ => Err(anyhow!("no version known for version hash: {version_hash}")),
    }
}

pub struct FedimintdCmd;
impl FedimintdCmd {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_FEDIMINTD_BASE_EXECUTABLE_ENV],
            &[FEDIMINTD_FALLBACK],
        ))
    }

    /// Returns the fedimintd version from clap or default min version
    pub async fn version_or_default() -> Version {
        match cmd!(FedimintdCmd, "--version").out_string().await {
            Ok(version) => parse_clap_version(&version),
            Err(_) => cmd!(FedimintdCmd, "version-hash")
                .out_string()
                .await
                .map(|v| version_hash_to_version(&v).unwrap_or(DEFAULT_VERSION))
                .unwrap_or(DEFAULT_VERSION),
        }
    }
}

pub struct Gatewayd;
impl Gatewayd {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_GATEWAYD_BASE_EXECUTABLE_ENV],
            &[GATEWAYD_FALLBACK],
        ))
    }

    /// Returns the gatewayd version from clap or default min version
    pub async fn version_or_default() -> Version {
        match cmd!(Gatewayd, "--version").out_string().await {
            Ok(version) => parse_clap_version(&version),
            Err(_) => cmd!(Gatewayd, "version-hash")
                .out_string()
                .await
                .map(|v| version_hash_to_version(&v).unwrap_or(DEFAULT_VERSION))
                .unwrap_or(DEFAULT_VERSION),
        }
    }
}

pub struct FedimintCli;
impl FedimintCli {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_MINT_CLIENT_ENV],
            &get_fedimint_cli_path()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        ))
    }

    /// Returns the fedimint-cli version from clap or default min version
    pub async fn version_or_default() -> Version {
        match cmd!(FedimintCli, "--version").out_string().await {
            Ok(version) => parse_clap_version(&version),
            Err(_) => DEFAULT_VERSION,
        }
    }

    pub async fn ws_status(self, endpoint: &str) -> Result<StatusResponse> {
        let status = cmd!(self, "admin", "dkg", "--ws", endpoint, "ws-status")
            .out_json()
            .await?;
        Ok(serde_json::from_value(status)?)
    }

    pub async fn set_password(self, auth: &ApiAuth, endpoint: &str) -> Result<()> {
        cmd!(
            self,
            "--password",
            &auth.0,
            "admin",
            "dkg",
            "--ws",
            endpoint,
            "set-password",
        )
        .run()
        .await
    }

    pub async fn set_config_gen_params(
        self,
        auth: &ApiAuth,
        endpoint: &str,
        meta: BTreeMap<String, String>,
        server_gen_params: ServerModuleConfigGenParamsRegistry,
    ) -> Result<()> {
        cmd!(
            self,
            "--password",
            &auth.0,
            "admin",
            "dkg",
            "--ws",
            endpoint,
            "set-config-gen-params",
            "--meta-json",
            serde_json::to_string(&meta)?,
            "--modules-json",
            serde_json::to_string(&server_gen_params)?
        )
        .run()
        .await
    }

    pub async fn consensus_config_gen_params(
        self,
        endpoint: &str,
    ) -> Result<ConfigGenParamsResponse> {
        let result = cmd!(
            self,
            "admin",
            "dkg",
            "--ws",
            endpoint,
            "consensus-config-gen-params"
        )
        .out_json()
        .await
        .context("non-json returned for consensus_config_gen_params")?;
        Ok(serde_json::from_value(result)?)
    }

    pub async fn get_default_config_gen_params(
        self,
        auth: &ApiAuth,
        endpoint: &str,
    ) -> Result<ConfigGenParamsRequest> {
        let result = cmd!(
            self,
            "--password",
            &auth.0,
            "admin",
            "dkg",
            "--ws",
            endpoint,
            "get-default-config-gen-params"
        )
        .out_json()
        .await
        .context("non-json returned for get_default_config_gen_params")?;
        Ok(serde_json::from_value(result)?)
    }

    pub async fn set_config_gen_connections(
        self,
        auth: &ApiAuth,
        endpoint: &str,
        our_name: &str,
        leader_api_url: Option<&str>,
    ) -> Result<()> {
        // FIXME: this should be a single command
        if let Some(leader_api_url) = leader_api_url {
            cmd!(
                self,
                "--password",
                &auth.0,
                "admin",
                "dkg",
                "--ws",
                endpoint,
                "set-config-gen-connections",
                "--our-name",
                our_name,
                "--leader-api-url",
                leader_api_url,
            )
            .run()
            .await
        } else {
            cmd!(
                self,
                "--password",
                &auth.0,
                "admin",
                "dkg",
                "--ws",
                endpoint,
                "set-config-gen-connections",
                "--our-name",
                our_name,
            )
            .run()
            .await
        }
    }

    pub async fn get_config_gen_peers(self, endpoint: &str) -> Result<Vec<PeerServerParams>> {
        let result = cmd!(
            self,
            "admin",
            "dkg",
            "--ws",
            endpoint,
            "get-config-gen-peers"
        )
        .out_json()
        .await
        .context("non-json returned for get_config_gen_peers")?;
        Ok(serde_json::from_value(result)?)
    }

    pub async fn run_dkg(self, auth: &ApiAuth, endpoint: &str) -> Result<()> {
        cmd!(
            self,
            "--password",
            &auth.0,
            "admin",
            "dkg",
            "--ws",
            endpoint,
            "run-dkg"
        )
        .run()
        .await
    }

    pub async fn get_verify_config_hash(
        self,
        auth: &ApiAuth,
        endpoint: &str,
    ) -> Result<BTreeMap<PeerId, bitcoincore_rpc::bitcoin::hashes::sha256::Hash>> {
        let result = cmd!(
            self,
            "--password",
            &auth.0,
            "admin",
            "dkg",
            "--ws",
            endpoint,
            "get-verify-config-hash"
        )
        .out_json()
        .await
        .context("non-json returned for get_verify_config_hash")?;
        Ok(serde_json::from_value(result)?)
    }

    pub async fn shutdown(self, auth: &ApiAuth, our_id: u64, session_count: u64) -> Result<()> {
        cmd!(
            self,
            "--password",
            &auth.0,
            "--our-id",
            our_id,
            "admin",
            "shutdown",
            session_count,
        )
        .run()
        .await
    }

    pub async fn status(self, auth: &ApiAuth, our_id: u64) -> Result<()> {
        cmd!(
            self,
            "--password",
            &auth.0,
            "--our-id",
            our_id,
            "admin",
            "status",
        )
        .run()
        .await
    }

    pub async fn start_consensus(self, auth: &ApiAuth, endpoint: &str) -> Result<()> {
        cmd!(
            self,
            "--password",
            &auth.0,
            "admin",
            "dkg",
            "--ws",
            endpoint,
            "start-consensus"
        )
        .run()
        .await
    }
}

pub struct LoadTestTool;
impl LoadTestTool {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_LOAD_TEST_TOOL_BASE_EXECUTABLE_ENV],
            &[LOAD_TEST_TOOL_FALLBACK],
        ))
    }
}

pub struct GatewayCli;
impl GatewayCli {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[],
            &get_gateway_cli_path()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        ))
    }

    /// Returns the gateway-cli version from clap or default min version
    pub async fn version_or_default() -> Version {
        match cmd!(GatewayCli, "--version").out_string().await {
            Ok(version) => parse_clap_version(&version),
            Err(_) => DEFAULT_VERSION,
        }
    }
}

pub struct GatewayClnExtension {
    default_path: String,
}

impl GatewayClnExtension {
    pub async fn default_path() -> String {
        cmd!("which", GATEWAY_CLN_EXTENSION_FALLBACK)
            .out_string()
            .await
            .expect("Failed to get gateway-cln-extension path")
    }

    async fn new() -> GatewayClnExtension {
        let default_path = GatewayClnExtension::default_path().await;
        GatewayClnExtension { default_path }
    }

    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[],
            &get_gateway_cln_extension_path(self.default_path.as_str())
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        ))
    }

    /// Returns the gateway-cln-extension version from clap or default min
    /// version
    pub async fn version_or_default() -> Version {
        // gateway-cln-extension did not handle --version correctly until v0.5.0
        // Without --version, we don't have a convenient way for determining the
        // version. To handle this, we only check the version for the extension
        // if gatewayd is > v0.5.0 since they should be on the same version.
        let gatewayd_version = crate::util::Gatewayd::version_or_default().await;
        if gatewayd_version < *VERSION_0_5_0_ALPHA {
            return Version::new(0, 4, 0);
        }

        match cmd!(GatewayClnExtension::new().await, "--version")
            .out_string()
            .await
        {
            Ok(version) => parse_clap_version(&version),
            // Default version for gateway-cln-extension is v0.4.0 because --version did not parse
            // correctly until v0.5.0
            Err(_) => Version::new(0, 4, 0),
        }
    }
}

pub struct GatewayClnCli;
impl GatewayClnCli {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_GWCLI_CLN_ENV],
            &["gateway-cln"],
        ))
    }
}

pub struct GatewayLndCli;
impl GatewayLndCli {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_GWCLI_LND_ENV],
            &["gateway-lnd"],
        ))
    }
}

pub struct LnCli;
impl LnCli {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_LNCLI_ENV],
            &get_lncli_path()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        ))
    }
}

pub struct ClnLightningCli;
impl ClnLightningCli {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_LIGHTNING_CLI_ENV],
            &get_lightning_cli_path()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        ))
    }
}

pub struct BitcoinCli;
impl BitcoinCli {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_BTC_CLIENT_ENV],
            &get_bitcoin_cli_path()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        ))
    }
}

pub struct Bitcoind;
impl Bitcoind {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_BITCOIND_BASE_EXECUTABLE_ENV],
            &[BITCOIND_FALLBACK],
        ))
    }
}

pub struct Lightningd;
impl Lightningd {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_LIGHTNINGD_BASE_EXECUTABLE_ENV],
            &[LIGHTNINGD_FALLBACK],
        ))
    }
}

pub struct Lnd;
impl Lnd {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_LND_BASE_EXECUTABLE_ENV],
            &[LND_FALLBACK],
        ))
    }
}

pub struct Electrs;
impl Electrs {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_ELECTRS_BASE_EXECUTABLE_ENV],
            &[ELECTRS_FALLBACK],
        ))
    }
}

pub struct Esplora;
impl Esplora {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_ESPLORA_BASE_EXECUTABLE_ENV],
            &[ESPLORA_FALLBACK],
        ))
    }
}

pub struct Recoverytool;
impl Recoverytool {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_RECOVERYTOOL_BASE_EXECUTABLE_ENV],
            &[RECOVERYTOOL_FALLBACK],
        ))
    }
}

pub struct Faucet;
impl Faucet {
    pub fn cmd(self) -> Command {
        to_command(get_command_str_for_alias(
            &[FM_FAUCET_BASE_EXECUTABLE_ENV],
            &[FAUCET_FALLBACK],
        ))
    }
}

fn get_command_str_for_alias(aliases: &[&str], default: &[&str]) -> Vec<String> {
    // try to use one of the aliases if set
    for alias in aliases {
        if let Ok(cmd) = std::env::var(alias) {
            return cmd.split_whitespace().map(ToOwned::to_owned).collect();
        }
    }
    // otherwise return the default value
    default.iter().map(ToString::to_string).collect()
}

fn to_command(cli: Vec<String>) -> Command {
    let mut cmd = tokio::process::Command::new(&cli[0]);
    cmd.args(&cli[1..]);
    Command {
        cmd,
        args_debug: cli,
    }
}

/// Returns true if running backwards-compatibility tests
pub fn is_backwards_compatibility_test() -> bool {
    is_env_var_set(FM_BACKWARDS_COMPATIBILITY_TEST_ENV)
}

/// Parses a version string returned from clap
/// ex: fedimintd 0.3.0-alpha -> 0.3.0-alpha
fn parse_clap_version(res: &str) -> Version {
    match res.split(' ').collect::<Vec<&str>>().as_slice() {
        [_binary, version] => Version::parse(version).unwrap_or(DEFAULT_VERSION),
        _ => DEFAULT_VERSION,
    }
}

#[test]
fn test_parse_clap_version() -> Result<()> {
    let version_str = "fedimintd 0.3.0-alpha";
    let expected_version = Version::parse("0.3.0-alpha")?;
    assert_eq!(expected_version, parse_clap_version(version_str));

    let version_str = "fedimintd 0.3.12";
    let expected_version = Version::parse("0.3.12")?;
    assert_eq!(expected_version, parse_clap_version(version_str));

    let version_str = "fedimint-cli 2.12.2-rc22";
    let expected_version = Version::parse("2.12.2-rc22")?;
    assert_eq!(expected_version, parse_clap_version(version_str));

    let version_str = "bad version";
    let expected_version = DEFAULT_VERSION;
    assert_eq!(expected_version, parse_clap_version(version_str));

    Ok(())
}
