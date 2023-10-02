use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::future::Future;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;
use std::{env, unreachable};

use anyhow::{bail, format_err, Context, Result};
use fedimint_core::task::{self, block_in_place};
use fedimint_logging::LOG_DEVIMINT;
use futures::executor::block_on;
use serde::de::DeserializeOwned;
use tokio::fs::OpenOptions;
use tokio::process::Child;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

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
        if let Some(mut child) = inner.child.take() {
            info!(
                target: LOG_DEVIMINT,
                "sending SIGTERM to {} and waiting for it to exit", inner.name
            );
            send_sigterm(&child);
            child.wait().await?;
        }
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

impl Drop for ProcessHandleInner {
    fn drop(&mut self) {
        let Some(child) = &mut self.child else {
            return;
        };
        let name = self.name.clone();
        block_in_place(move || {
            block_on(async move {
                info!(
                    target: LOG_DEVIMINT,
                    "sending SIGKILL to {name} and waiting for it to exit"
                );
                send_sigkill(child);
                if let Err(e) = child.wait().await {
                    warn!(target: LOG_DEVIMINT, "failed to wait for {name}: {e:?}");
                }
            })
        })
    }
}

pub struct ProcessManager {
    pub globals: super::vars::Global,
}

impl ProcessManager {
    pub fn new(globals: super::vars::Global) -> Self {
        Self { globals }
    }

    /// Logs to $FM_LOGS_DIR/{name}.{out,err}
    pub async fn spawn_daemon(&self, name: &str, mut cmd: Command) -> Result<ProcessHandle> {
        let logs_dir = env::var("FM_LOGS_DIR")?;
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
    pub fn arg<T: ToString>(mut self, arg: T) -> Self {
        let string = arg.to_string();
        self.cmd.arg(string.clone());
        self.args_debug.push(string);
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

    /// Run the command and get its output as json.
    pub async fn out_string(&mut self) -> Result<String> {
        let output = self
            .run_inner()
            .await
            .with_context(|| format!("command: {}", self.command_debug()))?;
        let output = String::from_utf8(output.stdout)?;
        Ok(output.trim().to_owned())
    }

    pub async fn run_inner(&mut self) -> Result<std::process::Output> {
        debug!(target: LOG_DEVIMINT, "> {}", self.command_debug());
        let output = self.cmd.output().await?;
        if !output.status.success() {
            bail!(
                "{}\nstdout:\n{}\nstderr:\n{}",
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
            .run_inner()
            .await
            .with_context(|| format!("command: {}", self.command_debug()))?;
        Ok(())
    }

    /// Run the command logging the output and error
    pub async fn run_with_logging(&mut self, name: String) -> Result<()> {
        let logs_dir = env::var("FM_LOGS_DIR")?;
        let path = format!("{logs_dir}/{name}.log");
        let log = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .await
            .with_context(|| format!("path: {} cmd: {}", path, name))?
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
            $this.cmd().await
                $(.arg($arg))*
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

const DEFAULT_RETRIES: usize = 20;
/// Will retry calling `f`.
/// - if `f` return Ok(val), this returns with Ok(val).
/// - if `f` return Err(Control::Break(err)), this returns Err(err)
/// - if `f` return Err(ControlFlow::Continue(err)), retries a maximum of
///   `retries` times.
pub async fn poll<Fut, R>(
    name: &str,
    retries: impl Into<Option<usize>>,
    f: impl Fn() -> Fut,
) -> Result<R>
where
    Fut: Future<Output = Result<R, ControlFlow<anyhow::Error, anyhow::Error>>>,
{
    let retries = retries.into().unwrap_or(DEFAULT_RETRIES);
    for i in 0.. {
        match f().await {
            Ok(value) => return Ok(value),
            Err(ControlFlow::Break(err)) => {
                return Err(err).with_context(|| format!("polling {name}"));
            }
            Err(ControlFlow::Continue(err)) if i <= retries => {
                debug!("polling {name} failed with: {err:?}, will retry... ({i}/{retries})");
                task::sleep(Duration::from_secs(1)).await;
            }
            Err(ControlFlow::Continue(err)) => {
                return Err(err).with_context(|| format!("polling {name} after {retries} retries"));
            }
        }
    }

    unreachable!();
}

// used to add `cmd` method.
pub trait ToCmdExt {
    type Fut;
    fn cmd(self) -> Self::Fut;
}

// a command that uses self as program name
impl ToCmdExt for &'_ str {
    type Fut = std::future::Ready<Command>;

    fn cmd(self) -> Self::Fut {
        std::future::ready(Command {
            cmd: tokio::process::Command::new(self),
            args_debug: vec![self.to_owned()],
        })
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

fn get_command_for_alias(alias: &str, default: &str) -> Command {
    // try to use alias if set
    let cli = std::env::var(alias)
        .map(|s| s.split_whitespace().map(ToOwned::to_owned).collect())
        .unwrap_or_else(|_| vec![default.into()]);
    let mut cmd = tokio::process::Command::new(&cli[0]);
    cmd.args(&cli[1..]);
    Command {
        cmd,
        args_debug: cli,
    }
}

pub struct FedimintCli;
impl FedimintCli {
    pub async fn cmd(self) -> Command {
        get_command_for_alias("FM_MINT_CLIENT", "fedimint-cli")
    }
}

pub struct LnCli;
impl LnCli {
    pub async fn cmd(self) -> Command {
        get_command_for_alias("FM_LNCLI", "lncli")
    }
}

pub struct ClnLightningCli;
impl ClnLightningCli {
    pub async fn cmd(self) -> Command {
        get_command_for_alias("FM_LIGHTNING_CLI", "lightning-cli")
    }
}

pub struct GatewayClnCli;
impl GatewayClnCli {
    pub async fn cmd(self) -> Command {
        get_command_for_alias("FM_GWCLI_CLN", "gateway-cln")
    }
}

pub struct GatewayLndCli;
impl GatewayLndCli {
    pub async fn cmd(self) -> Command {
        get_command_for_alias("FM_GWCLI_LND", "gateway-lnd")
    }
}
