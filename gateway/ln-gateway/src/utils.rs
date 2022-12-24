use std::{future::Future, path::PathBuf, result::Result, time::Duration};

use clap::{Arg, Command};
use fedimint_server::config::load_from_file;
use tokio::time::sleep;
use tracing::info;

use crate::config::GatewayConfig;

/// Retry an operation util the operation succeeds, OR
/// The maximum number of attempts are made without success
pub async fn retry<F, R, T>(
    op_name: String,
    op_fn: F,
    wait: Duration,
    max_retries: u32,
) -> Result<T, anyhow::Error>
where
    F: Fn() -> R,
    R: Future<Output = Result<T, anyhow::Error>>,
{
    let mut att = 0;
    loop {
        match op_fn().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                att += 1;
                if att > max_retries {
                    return Err(e);
                }
                info!(
                    "{} failed with error: {}. Retrying in {} seconds",
                    op_name,
                    e,
                    wait.as_secs()
                );
                sleep(wait).await;
            }
        }
    }
}

const WORK_DIR: &str = "GATEWAY_DIR";

pub fn try_read_gateway_dir() -> Result<PathBuf, anyhow::Error> {
    // TODO: Try read gateway directory from environment variable
    let matched = Command::new("gateway-dir")
        .arg(
            Arg::new("dir")
                .short('d')
                .long("dir")
                .value_name(WORK_DIR)
                .help("Specify a work directory for the gateway"),
        )
        .get_matches();

    let work_dir = matched
        .get_one::<String>("dir")
        .expect("Missing gateway directory")
        .parse::<PathBuf>()
        .expect("Invalid gateway directory");

    Ok(work_dir)
}

pub fn read_gateway_config(work_dir: Option<PathBuf>) -> Result<GatewayConfig, anyhow::Error> {
    let dir = work_dir.unwrap_or_else(|| try_read_gateway_dir().unwrap());

    let gw_cfg_path = dir.join("gateway.config");
    let gw_cfg: GatewayConfig = load_from_file(&gw_cfg_path).expect("Failed to parse config");

    Ok(gw_cfg)
}
