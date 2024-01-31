use std::env;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use devimint::cli::CommonArgs;
use fedimint_core::util::write_overwrite_async;
use fedimint_logging::LOG_DEVIMINT;
use tracing::warn;

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
    pub const CODE_VERSION: &str = env!("FEDIMINT_BUILD_CODE_VERSION");

    let mut args = std::env::args();
    if let Some(ref arg) = args.nth(1) {
        if arg.as_str() == "version-hash" {
            println!("{CODE_VERSION}");
            std::process::exit(0);
        }
    }
    match handle_command().await {
        Ok(r) => Ok(r),
        Err(e) => {
            if let Ok(test_dir) = env::var("FM_TEST_DIR") {
                let ready_file = PathBuf::from(test_dir).join("ready");
                write_overwrite_async(ready_file, "ERROR").await?;
            } else {
                warn!(target: LOG_DEVIMINT, "FM_TEST_DIR was not set");
            }
            Err(e)
        }
    }
}
