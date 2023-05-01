use std::ffi::OsStr;

use anyhow::{anyhow, bail};
use serde::de::DeserializeOwned;
use tokio::fs::OpenOptions;
use tokio::process::Child;
use tracing::warn;

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
pub struct ProcessHandle(Arc<ProcessHandleInner>);

impl ProcessHandle {
    pub async fn kill(self) -> Result<()> {
        let arc_process_handle_inner = self.0;
        let mut process_handle_inner = match Arc::try_unwrap(arc_process_handle_inner) {
            Ok(process_handler_inner) => process_handler_inner,
            Err(_) => return Err(anyhow!("Cannot kill process because of clones")),
        };
        let mut child = std::mem::take(&mut process_handle_inner.child).unwrap();
        info!(LOG_TEST, "killing {}", process_handle_inner.name);
        kill(&child);
        child.wait().await?;
        Ok(())
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
        info!(LOG_TEST, "killing {}", self.name);
        kill(child);
    }
}

#[derive(Default)]
pub struct ProcessManager {}

impl ProcessManager {
    pub fn new() -> Self {
        Self {}
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
        let child = cmd.cmd.spawn()?;
        Ok(ProcessHandle(Arc::new(ProcessHandleInner {
            name: name.to_owned(),
            child: Some(child),
        })))
    }
}

pub struct Command {
    pub cmd: tokio::process::Command,
    args_debug: Vec<String>,
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
        let output = self.run_inner().await?;
        let output = String::from_utf8(output.stdout)?;
        Ok(output.trim().to_owned())
    }

    pub async fn run_inner(&mut self) -> Result<std::process::Output> {
        info!(LOG_TEST, "> {}", self.command_debug());
        let output = self.cmd.output().await?;
        if !output.status.success() {
            bail!(
                "{}\ncommand: {}\nstdout:\n{}\nstderr:\n{}",
                output.status,
                self.command_debug(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
        }
        Ok(output)
    }

    /// Run the command ignoring its output.
    pub async fn run(&mut self) -> Result<()> {
        let _ = self.run_inner().await?;
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

        }
    };
}

const POLL_INTERVAL: Duration = Duration::from_millis(200);

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
        if now.duration_since(last_time)? > Duration::from_secs(20) {
            let total_duration = now.duration_since(start)?;
            warn!(
                LOG_TEST,
                "waiting {name} for over {} seconds",
                total_duration.as_secs()
            );
            last_time = now;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
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
