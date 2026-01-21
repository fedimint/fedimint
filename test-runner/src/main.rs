use std::env::current_exe;
use std::fmt::Write;
use std::io::{IsTerminal, stdout};
use std::process::Stdio;
use std::str::FromStr;
use std::thread::available_parallelism;
use std::{env, fs};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use devimint::cmd;
use fedimint_core::envs::is_env_var_set;
use nix::sys::resource::Resource::RLIMIT_NOFILE;
use nix::sys::resource::{self};
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use tempfile::tempdir;
use tokio::io::AsyncWriteExt;
use tokio::process::ChildStdin;
use tracing::{info, warn};

mod test_wrapper;
mod tests;
mod upgrade_tests;
mod util;
mod versions;

use util::set_env;

use crate::upgrade_tests::UpgradePath;

#[derive(Parser)]
#[command(about = "Run fedimint integration tests in parallel")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run all tests in parallel
    Run(RunTestsArgs),
    RunUpgrade(RunUpgradeArgs),

    /// Run a single test (called by parallel)
    #[clap(hide = true)]
    RunOne {
        data: RunTestData,
    },
}

/// Test command are sent as json over clap
#[derive(Serialize, Deserialize, Clone)]
enum RunTestData {
    Normal(tests::TestArgs),
    Upgrade(upgrade_tests::UpgradeTest),
}

impl FromStr for RunTestData {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
}

#[derive(Parser, Debug)]
pub struct RunTestsArgs {
    /// Previous versions to run backwards compat with.
    #[arg(num_args = 0.., value_delimiter = ' ')]
    previous_versions: Vec<semver::Version>,

    /// Use full version matrix instead of partial
    #[arg(long, env = "FM_FULL_VERSION_MATRIX")]
    full_matrix: bool,

    /// Number of times to run the test suite
    #[arg(long, env = "FM_TEST_RUNNER_TIMES", default_value = "1")]
    times: usize,

    #[clap(flatten)]
    parallel_args: ParallelArgs,
}

#[derive(Parser, Debug)]
pub struct RunUpgradeArgs {
    /// Upgrade paths to tests.
    #[arg(num_args = 1.., value_delimiter = ' ')]
    upgrade_paths: Vec<UpgradePath>,

    #[clap(flatten)]
    parallel_args: ParallelArgs,
}

#[derive(Parser, Debug)]
struct ParallelArgs {
    /// Number of parallel jobs (default: nproc/2 + 1)
    #[arg(long, env = "FM_TEST_RUNNER_JOBS")]
    jobs: Option<usize>,

    /// Timeout per test in seconds
    #[arg(long, env = "FM_TEST_RUNNER_TIMEOUT", default_value = "360")]
    timeout: u32,

    /// Max system load
    #[arg(long, env = "FM_TEST_RUNNER_MAX_LOAD")]
    max_load: Option<usize>,

    /// Delay between starting tests
    #[arg(long, env = "FM_TEST_RUNNER_DELAY", default_value = "0.5")]
    delay: f32,

    /// Show ETA (disabled in CI)
    #[arg(long, env = "FM_TEST_RUNNER_DISABLE_ETA")]
    disable_eta: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => tests::run_all_tests(args).await,
        Command::RunUpgrade(args) => upgrade_tests::run_all_tests(args).await,
        Command::RunOne { data } => match data {
            RunTestData::Normal(test_args) => tests::run_one_test(test_args).await,
            RunTestData::Upgrade(upgrade_test) => upgrade_tests::run_one_test(upgrade_test).await,
        },
    }
}

/// Basic env for all tests
fn setup_basic_environment() -> Result<()> {
    let env_vars = [
        ("LANG", "C"),
        ("FM_IROH_ENABLE_DHT", "false"),
        ("FM_IROH_ENABLE_NEXT", "false"),
        ("FM_IROH_DHT_ENABLE", "false"),
        ("FM_IROH_NEXT_ENABLE", "false"),
        ("FM_IROH_RELAYS_ENABLE", "false"),
        ("FM_IROH_N0_DISCOVERY_ENABLE", "false"),
        ("FM_IROH_PKARR_RESOLVER_ENABLE", "false"),
        ("FM_IROH_PKARR_PUBLISHER_ENABLE", "false"),
    ];

    for (key, value) in env_vars {
        set_env(key, value);
    }

    let rust_log = env::var("RUST_LOG").unwrap_or_default();
    set_env("RUST_LOG", format!("fm::test=debug,info,{rust_log}"));

    let home = env::var("HOME").expect("home must be set");
    let parallel_dir = format!("{home}/.parallel");
    fs::create_dir_all(&parallel_dir)?;
    fedimint_core::util::write_new(format!("{parallel_dir}/will-cite"), "").ok();

    Ok(())
}

fn update_resource_limit() -> Result<()> {
    let (soft_limit, hard_limit) = resource::getrlimit(RLIMIT_NOFILE)?;
    if soft_limit < 10000 {
        warn!("ulimit too small, changing it to 10000");
        resource::setrlimit(RLIMIT_NOFILE, 10000, hard_limit)?;
    }
    Ok(())
}

async fn prebuild_cargo_workspace() -> Result<()> {
    if is_env_var_set("SKIP_CARGO_BUILD") {
        info!("SKIP_CARGO_BUILD set, skipping building workspace");
        return Ok(());
    }

    let cargo_profile = env::var("CARGO_PROFILE").unwrap_or_else(|_| "dev".to_string());

    info!("Pre-building workspace...");
    cmd!(
        "cargo",
        "build",
        "--workspace",
        "--all-targets",
        "--profile={cargo_profile}"
    )
    .run()
    .await?;

    info!("Pre-building tests...");
    cmd!(
        "cargo",
        "nextest",
        "run",
        "--no-run",
        "--workspace",
        "--all-targets",
        "--cargo-profile={cargo_profile}",
        "--profile={cargo_profile}"
    )
    .run()
    .await?;

    set_env("CARGO_DENY_COMPILATION", "1");
    add_target_dir_to_path();
    Ok(())
}

fn add_target_dir_to_path() {
    let cargo_profile = env::var("CARGO_PROFILE").unwrap_or_else(|_| "dev".to_string());
    set_env(
        "PATH",
        format!(
            "{target_dir}/{profile_dir}:{path}",
            path = env::var("PATH").unwrap_or_default(),
            target_dir =
                env::var("CARGO_BUILD_TARGET_DIR").unwrap_or_else(|_| "target".to_string()),
            profile_dir = if cargo_profile == "dev" {
                "debug"
            } else {
                &cargo_profile
            },
        ),
    );
}

/// Run all tests in parallel using parallel command.
async fn run_tests_with_parallel(args: &ParallelArgs, mut tests: Vec<RunTestData>) -> Result<()> {
    let nproc = available_parallelism().map(|n| n.get()).unwrap_or(4);

    let in_ci = is_env_var_set("CI") || env::var("CARGO_PROFILE").as_deref() == Ok("ci");
    let tmpdir = tempdir()?;
    let joblog = tmpdir.path().join("joblog");

    let mut parallel_cmd = cmd!(
        "parallel",
        "--halt-on-error",
        "1",
        "--joblog",
        joblog.to_str().unwrap(),
        "--jobs",
        args.jobs.unwrap_or(nproc / 2 + 1),
        "--timeout",
        args.timeout,
        "--load",
        args.max_load.unwrap_or(nproc),
        "--delay",
        args.delay,
    );

    if !in_ci && !args.disable_eta && stdout().is_terminal() {
        parallel_cmd = parallel_cmd.arg(&"--eta");
    }

    eprintln!("Starting all tests in parallel...");

    tests.shuffle(&mut thread_rng());

    let mut child = parallel_cmd
        .cmd
        .stdin(Stdio::piped())
        .spawn()
        .context("failed to spawn parallel")?;
    write_test_commands_into_parallel(child.stdin.as_mut().unwrap(), tests).await?;

    let status = child.wait().await.context("Failed to wait for parallel")?;

    if status.success() {
        eprintln!("All tests successful");
        Ok(())
    } else {
        eprintln!("Some tests failed:");
        if let Ok(joblog) = fs::read_to_string(&joblog) {
            for line in joblog.lines() {
                if line
                    .split('\t')
                    .nth(6)
                    .is_some_and(|exit_val| exit_val != "0")
                {
                    eprintln!("{line}");
                }
            }
        }
        bail!("Some tests failed");
    }
}

async fn write_test_commands_into_parallel(
    stdin: &mut ChildStdin,
    tests: Vec<RunTestData>,
) -> anyhow::Result<()> {
    let current_exe = current_exe()?;
    let current_exe = current_exe.to_str().expect("expect must be valid utf8");

    let mut stdin_data = String::new();
    for test in tests {
        writeln!(
            stdin_data,
            "{current_exe} run-one {}",
            serde_json::to_string(&test)?,
        )?;
    }

    stdin.write_all(stdin_data.as_bytes()).await?;
    Ok(())
}
