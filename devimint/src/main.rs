use std::env;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use devimint::cli::CommonArgs;
use devimint::envs::FM_TEST_DIR_ENV;
use fedimint_core::fedimint_build_code_version_env;
use fedimint_core::util::{handle_version_hash_command, write_overwrite_async};
use fedimint_logging::LOG_DEVIMINT;
use tokio::time::Instant;
use tracing::{debug, warn};

#[derive(Parser)]
#[command(version)]
struct Args {
    #[clap(subcommand)]
    command: Cmd,
    #[clap(flatten)]
    common: CommonArgs,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// Run a base devimint command.
    #[clap(flatten)]
    Base(devimint::cli::Cmd),
    /// Run a test.
    #[clap(flatten)]
    Test(devimint::tests::TestCmd),
}

impl Cmd {
    fn setup_test_dir(&self, common_args: &CommonArgs) -> Option<PathBuf> {
        match self {
            Cmd::Base(
                devimint::cli::Cmd::ExternalDaemons { .. }
                | devimint::cli::Cmd::DevFed { .. }
                | devimint::cli::Cmd::DevFedPreRestore { .. },
            )
            | Cmd::Test(_) => Some(common_args.test_dir()),
            Cmd::Base(devimint::cli::Cmd::Rpc(_)) => None,
        }
    }
}

async fn handle_command(args: Args) -> (anyhow::Result<()>, Option<PathBuf>) {
    let setup_test_dir = args.command.setup_test_dir(&args.common);
    let result = match args.command {
        Cmd::Base(base) => devimint::cli::handle_command(base, args.common).await,
        Cmd::Test(test) => devimint::tests::handle_command(test, args.common).await,
    };
    (result, setup_test_dir)
}

async fn write_error_marker(test_dir: Option<PathBuf>) -> anyhow::Result<()> {
    let test_dir = test_dir.or_else(|| env::var(FM_TEST_DIR_ENV).ok().map(PathBuf::from));
    if let Some(test_dir) = test_dir {
        let ready_file = test_dir.join("ready");
        write_overwrite_async(ready_file, "ERROR").await?;
    } else {
        warn!(target: LOG_DEVIMINT, "{}", &format!("{FM_TEST_DIR_ENV} was not set"));
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let start_time = Instant::now();
    handle_version_hash_command(fedimint_build_code_version_env!());
    let (command_result, setup_test_dir) = handle_command(Args::parse()).await;
    let res = match command_result {
        Ok(r) => Ok(r),
        Err(e) => {
            write_error_marker(setup_test_dir).await?;
            Err(e)
        }
    };
    debug!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed().as_millis(), "Finished");
    res
}
