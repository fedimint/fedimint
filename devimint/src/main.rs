use std::env;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use devimint::cli::CommonArgs;
use devimint::envs::FM_TEST_DIR_ENV;
use fedimint_core::fedimint_build_code_version_env;
use fedimint_core::util::{handle_version_hash_command, write_overwrite_async};
use fedimint_logging::LOG_DEVIMINT;
use tokio::time::Instant;
use tracing::{debug, trace, warn};

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

async fn handle_command() -> anyhow::Result<()> {
    let args = Args::parse();
    match args.command {
        Cmd::Base(base) => devimint::cli::handle_command(base, args.common).await,
        Cmd::Test(test) => devimint::tests::handle_command(test, args.common).await,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    trace!(target: LOG_DEVIMINT, "Started");
    let start_time = Instant::now();
    handle_version_hash_command(fedimint_build_code_version_env!());
    let res = match handle_command().await {
        Ok(r) => Ok(r),
        Err(e) => {
            if let Ok(test_dir) = env::var(FM_TEST_DIR_ENV) {
                let ready_file = PathBuf::from(test_dir).join("ready");
                write_overwrite_async(ready_file, "ERROR").await?;
            } else {
                warn!(target: LOG_DEVIMINT, "{}", &format!("{} was not set", FM_TEST_DIR_ENV));
            }
            Err(e)
        }
    };
    debug!(target: LOG_DEVIMINT, elapsed_ms = %start_time.elapsed().as_millis(), "Finished");
    res
}
