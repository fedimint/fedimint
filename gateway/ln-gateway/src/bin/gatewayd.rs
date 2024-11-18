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
#[cfg(not(target_env = "msvc"))]
use jemallocator::Jemalloc;
use ln_gateway::Gateway;
use tracing::info;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
// rocksdb suffers from memory fragmentation when using standard allocator
static GLOBAL: Jemalloc = Jemalloc;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    handle_version_hash_command(fedimint_build_code_version_env!());
    TracingSetup::default().init()?;
    let tg = TaskGroup::new();
    tg.install_kill_handler();
    let gatewayd = Gateway::new_with_default_modules().await?;
    let shutdown_receiver = gatewayd.clone().run(&tg).await?;
    shutdown_receiver.await;
    gatewayd.unannounce_from_all_federations().await;
    info!("Gatewayd exiting...");
    Ok(())
}
