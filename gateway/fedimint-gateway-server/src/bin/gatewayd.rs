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
use fedimint_gateway_server::Gateway;
use fedimint_logging::{LOG_GATEWAY, TracingSetup};
use tracing::info;

#[cfg(feature = "jemalloc")]
#[global_allocator]
// rocksdb suffers from memory fragmentation when using standard allocator
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() -> Result<(), anyhow::Error> {
    let runtime = Arc::new(tokio::runtime::Runtime::new()?);
    runtime.block_on(async {
        handle_version_hash_command(fedimint_build_code_version_env!());
        TracingSetup::default().init()?;
        let (mnemonic_sender, mnemonic_receiver) = tokio::sync::broadcast::channel::<()>(4);
        let gatewayd = Gateway::new_with_default_modules(mnemonic_sender).await?;
        let shutdown_receiver = gatewayd
            .clone()
            .run(runtime.clone(), mnemonic_receiver)
            .await?;
        shutdown_receiver.await;
        gatewayd.unannounce_from_all_federations().await;
        info!(target: LOG_GATEWAY, "Gatewayd exiting...");
        Ok(())
    })
}
