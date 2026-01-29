use std::env::current_exe;
use std::io::{IsTerminal, stdout};
use std::process::Stdio;
use std::thread::available_parallelism;
use std::{env, fs};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use devimint::cmd;
use fedimint_core::envs::is_env_var_set;
use itertools::iproduct;
use nix::sys::resource::Resource::RLIMIT_NOFILE;
use nix::sys::resource::{self};
use rand::seq::SliceRandom;
use rand::thread_rng;
use tempfile::tempdir;
use tokio::io::AsyncWriteExt;
use tokio::process::ChildStdin;
use tracing::{info, warn};

mod test_wrapper;
mod tests;
mod util;
mod versions;

use tests::{RunOneArgs, TestId, run_one_test};
use util::set_env;
use versions::{
    ComponentVersions, build_previous_versions_with_nix, generate_backward_compat_version_matrix,
};

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
    /// Run a single test (called by parallel)
    #[clap(hide = true)]
    RunOne(RunOneArgs),
}

#[derive(Parser)]
struct RunTestsArgs {
    /// Previous versions to run backwards compat with.
    #[arg(num_args = 0..)]
    previous_versions: Vec<semver::Version>,

    /// Use full version matrix instead of partial
    #[arg(long, env = "FM_FULL_VERSION_MATRIX")]
    full_matrix: bool,

    /// Number of parallel jobs (default: nproc/2 + 1)
    #[arg(long, env = "FM_TEST_CI_ALL_JOBS")]
    jobs: Option<usize>,

    /// Timeout per test in seconds
    #[arg(long, env = "FM_TEST_CI_ALL_TIMEOUT", default_value = "360")]
    timeout: u32,

    /// Max system load
    #[arg(long, env = "FM_TEST_CI_ALL_MAX_LOAD")]
    max_load: Option<usize>,

    /// Delay between starting tests
    #[arg(long, env = "FM_TEST_CI_ALL_DELAY", default_value = "0.5")]
    delay: f32,

    /// Number of times to run the test suite
    #[arg(long, env = "FM_TEST_CI_ALL_TIMES", default_value = "1")]
    times: usize,

    /// Show ETA (disabled in CI)
    #[arg(long, env = "FM_TEST_CI_ALL_DISABLE_ETA")]
    disable_eta: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run(args) => run_tests(args).await,
        Command::RunOne(args) => run_one_test(args).await,
    }
}

async fn run_tests(args: RunTestsArgs) -> Result<()> {
    fedimint_logging::TracingSetup::default().init()?;
    setup_basic_environment()?;
    update_resource_limit()?;
    prebuild_cargo_workspace().await?;
    build_previous_versions_with_nix(&args.previous_versions).await?;
    let matrix = if args.previous_versions.is_empty() {
        vec![ComponentVersions::all_current()]
    } else {
        generate_backward_compat_version_matrix(args.previous_versions.clone(), args.full_matrix)
    };

    run_tests_with_parallel(&args, generate_test_commands(&matrix, args.times)).await
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

fn generate_test_commands(matrix: &[ComponentVersions], times: usize) -> Vec<RunOneArgs> {
    let tests = TestId::all();
    let mut commands = Vec::new();

    for (_, versions) in iproduct!(0..times, matrix) {
        let enable_lnv2_flags = if versions.is_all_current() {
            vec![true]
        } else if versions.supports_lnv2() {
            vec![false, true]
        } else {
            vec![false]
        };

        for (test, enable_lnv2) in iproduct!(tests, enable_lnv2_flags) {
            commands.push(RunOneArgs {
                test: *test,
                fed_version: versions.fed.clone(),
                gateway_version: versions.gateway.clone(),
                client_version: versions.client.clone(),
                enable_lnv2,
            });
        }
    }

    commands
}

/// Run all tests in parallel using parallel command.
async fn run_tests_with_parallel(args: &RunTestsArgs, mut tests: Vec<RunOneArgs>) -> Result<()> {
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

    // write all command for parallel
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
    tests: Vec<RunOneArgs>,
) -> anyhow::Result<()> {
    use std::fmt::Write;

    use clap::ValueEnum;

    let current_exe = current_exe()?;
    let current_exe = current_exe.to_str().expect("expect must be valid utf8");

    let mut stdin_data = String::new();
    for test in tests {
        let test_value = test.test.to_possible_value().expect("test has value");
        writeln!(
            stdin_data,
            "{current_exe} run-one {} --fed-version={} --client-version={} --gateway-version={} --enable-lnv2={}",
            test_value.get_name(),
            test.fed_version,
            test.client_version,
            test.gateway_version,
            test.enable_lnv2,
        )?;
    }

    stdin.write_all(stdin_data.as_bytes()).await?;
    Ok(())
}
