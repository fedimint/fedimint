use std::ffi::OsStr;
use std::sync::Weak;

use anyhow::bail;
use fedimint_core::task;
use serde::de::DeserializeOwned;
use tokio::fs::OpenOptions;
use tokio::process::Child;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::*;

fn kill(child: &Child) {
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id().expect("pid should be present") as _),
        nix::sys::signal::Signal::SIGTERM,
    );
}

/// Kills process when all references to ProcessHandle are dropped.
///
/// NOTE: drop order is significant make sure fields in struct are declared in
/// correct order it is generallly clients, process handle, deps
#[derive(Debug, Clone)]
pub struct ProcessHandle(Arc<Mutex<ProcessHandleInner>>);

impl ProcessHandle {
    pub fn as_weak(&self) -> WeakProcessHandle {
        WeakProcessHandle(Arc::downgrade(&self.0))
    }

    pub async fn kill(&self) -> Result<()> {
        let mut inner = self.0.lock().await;
        if let Some(mut child) = inner.child.take() {
            info!(LOG_DEVIMINT, "killing {}", inner.name);
            kill(&child);
            child.wait().await?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct WeakProcessHandle(Weak<Mutex<ProcessHandleInner>>);

impl WeakProcessHandle {
    pub fn upgrade(&self) -> Option<ProcessHandle> {
        self.0.upgrade().map(ProcessHandle)
    }

    pub async fn kill(&self) -> Result<()> {
        if let Some(handle) = self.upgrade() {
            handle.kill().await
        } else {
            // Process must have already been killed
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct ProcessHandleInner {
    name: String,
    child: Option<Child>,
}

impl Drop for ProcessHandleInner {
    fn drop(&mut self) {
        let Some(child) = &mut self.child else { return; };
        info!(LOG_DEVIMINT, "killing {}", self.name);
        kill(child);
    }
}

#[derive(Clone)]
pub struct ProcessManager {
    pub globals: Arc<vars::Global>,
    handles: Arc<Mutex<Vec<WeakProcessHandle>>>,
}

impl ProcessManager {
    pub fn new(globals: vars::Global) -> Self {
        Self {
            globals: Arc::new(globals),
            handles: Arc::new(Mutex::new(Vec::new())),
        }
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
        self.handles.lock().await.push(handle.as_weak());
        Ok(handle)
    }

    pub async fn kill_all_children(&self) {
        let handles = self.handles.lock().await;
        let killing_jobs = handles.iter().map(|handle| handle.kill());
        for result in futures::future::join_all(killing_jobs).await {
            if let Err(e) = result {
                warn!(LOG_DEVIMINT, "failed to kill child: {e:?}");
            }
        }
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
        debug!(LOG_DEVIMINT, "> {}", self.command_debug());
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
            .open(path)
            .await?
            .into_std()
            .await;
        self.cmd.stdout(log.try_clone()?);
        self.cmd.stderr(log);
        let status = self.cmd.spawn()?.wait().await?;
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

const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Will retry calling `f` until it returns `Ok(true)` or `retries` times.
/// A notable difference from [`poll`] is that `f` may fail with an error at any
/// time and we will still keep retrying.
pub async fn poll_max_retries<Fut>(name: &str, retries: usize, f: impl Fn() -> Fut) -> Result<()>
where
    Fut: Future<Output = Result<bool>>,
{
    let mut i = 0;
    loop {
        let result = f().await;
        if i == retries - 1 {
            match result {
                Ok(true) => return Ok(()),
                Ok(false) => {
                    bail!("{name} failed to reach good state after {retries} retries");
                }
                Err(e) => {
                    bail!("{name} failed after {retries} retries with: {e:?}");
                }
            }
        } else {
            match result {
                Ok(true) => return Ok(()),
                other => {
                    i += 1;
                    debug!("polling {name} failed with: {other:?}, will retry... ({i}/{retries})");
                    task::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
}

pub async fn poll<Fut>(name: &str, f: impl Fn() -> Fut) -> Result<()>
where
    Fut: Future<Output = Result<bool>>,
{
    poll_value(name, || async { Ok(f().await?.then_some(())) }).await?;
    Ok(())
}

pub async fn poll_value<Fut, R>(name: &str, f: impl Fn() -> Fut) -> Result<R>
where
    Fut: Future<Output = Result<Option<R>>>,
{
    let start = fedimint_core::time::now();
    let mut last_time = start;
    loop {
        if let Some(output) = f().await? {
            break Ok(output);
        }
        // report every 20 seconds
        let now = fedimint_core::time::now();
        if now.duration_since(last_time).unwrap_or_default() > Duration::from_secs(20) {
            let total_duration = now.duration_since(start).unwrap_or_default();
            warn!(
                LOG_DEVIMINT,
                "waiting {name} for over {} seconds",
                total_duration.as_secs()
            );
            last_time = now;
        }
        task::sleep(POLL_INTERVAL).await;
    }
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
