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
use fedimint_core::util::{handle_version_hash_command, FmtCompact};
use fedimint_gateway_server::Gateway;
use fedimint_logging::{LOG_GATEWAY, TracingSetup};
#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
use tikv_jemallocator::Jemalloc;
use tracing::{error, info};

#[cfg(not(any(target_env = "msvc", target_os = "ios", target_os = "android")))]
#[global_allocator]
// rocksdb suffers from memory fragmentation when using standard allocator
static GLOBAL: Jemalloc = Jemalloc;

fn main() -> Result<(), anyhow::Error> {
    let runtime = tokio::runtime::Runtime::new()?;
    let handle = runtime.handle().clone();
    runtime.block_on(async {
        handle_version_hash_command(fedimint_build_code_version_env!());
        TracingSetup::default().init()?;
        let (mnemonic_sender, mnemonic_receiver) = tokio::sync::broadcast::channel(4);
        let gatewayd = Gateway::new_with_default_modules(mnemonic_sender).await?;
        let shutdown_receiver = gatewayd
            .clone()
            .run(handle, mnemonic_receiver)
            .await?;
        shutdown_receiver.await;
        gatewayd.unannounce_from_all_federations().await;
        if let Err(err) = gatewayd.task_group().shutdown_join_all(None).await {
            error!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Error waiting for gateway task group to shut down");
        }
        info!(target: LOG_GATEWAY, "Gatewayd exiting...");
        Ok(())
    })
}
