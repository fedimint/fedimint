#![warn(missing_docs)]
//! This crate provides `gatewayd`, the Fedimint gateway binary.
//!
//! The binary contains logic for sending/receiving Lightning payments on behalf
//! of Fedimint clients in one or more connected Federations.
//!
//! It runs a webserver with a REST API that can be used by Fedimint
//! clients to request routing of payments through the Lightning Network.
//! The API also has endpoints for managing the gateway.

use fedimint_core::fedimint_build_code_version_env;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::handle_version_hash_command;
use fedimint_logging::TracingSetup;
use ln_gateway::Gateway;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    handle_version_hash_command(fedimint_build_code_version_env!());
    TracingSetup::default().init()?;
    let mut tg = TaskGroup::new();
    tg.install_kill_handler();
    let gatewayd = Gateway::new_with_default_modules().await?;
    let shutdown_receiver = gatewayd.clone().run(&mut tg).await?;
    shutdown_receiver.await;
    gatewayd.leave_all_federations().await;
    info!("Gatewayd exiting...");
    Ok(())
}
