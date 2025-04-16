#![warn(missing_docs)]
//! This crate provides `gatewayd`, the Fedimint gateway binary.
//!
//! The binary contains logic for sending/receiving Lightning payments on behalf
//! of Fedimint clients in one or more connected Federations.
//!
//! It runs a webserver with a REST API that can be used by Fedimint
//! clients to request routing of payments through the Lightning Network.
//! The API also has endpoints for managing the gateway.

use std::sync::Arc;

use fedimint_core::fedimint_build_code_version_env;
use fedimint_core::util::handle_version_hash_command;
use fedimint_logging::TracingSetup;
use ln_gateway::Gateway;
#[cfg(not(any(target_env = "msvc", target_os = "ios")))]
use tikv_jemallocator::Jemalloc;
use tracing::info;

#[cfg(not(any(target_env = "msvc", target_os = "ios")))]
#[global_allocator]
// rocksdb suffers from memory fragmentation when using standard allocator
static GLOBAL: Jemalloc = Jemalloc;

fn main() -> Result<(), anyhow::Error> {
    let runtime = Arc::new(tokio::runtime::Runtime::new()?);
    runtime.block_on(async {
        handle_version_hash_command(fedimint_build_code_version_env!());
        TracingSetup::default().init()?;
        let gatewayd = Gateway::new_with_default_modules().await?;
        let shutdown_receiver = gatewayd.clone().run(runtime.clone()).await?;
        shutdown_receiver.await;
        gatewayd.unannounce_from_all_federations().await;
        info!("Gatewayd exiting...");
        Ok(())
    })
}
