use std::future::pending;
use std::time::Duration;

use anyhow::format_err;
use fedimint_core::runtime;
use fedimint_core::util::{backoff_util, retry};
use fedimint_logging::LOG_CLIENT;
use fedimint_wallet_client::WalletClientModule;
use fedimint_wallet_client::api::WalletFederationApi;
use tracing::info;

use crate::cli::Opts;
use crate::{CliOutput, CliOutputResult, CliResultExt, FedimintCli};

impl FedimintCli {
    /// Retry the wallet consensus height, reopening the client for each
    /// attempt.
    pub(super) async fn wait_block_count(&self, cli: &Opts, target: u64) -> CliOutputResult {
        retry(
            "wait_block_count",
            backoff_util::custom_backoff(Duration::from_millis(100), Duration::from_secs(5), None),
            || async {
                let client = self.client_open(cli).await?;
                let wallet = client.get_first_module::<WalletClientModule>()?;
                let count = client
                    .api()
                    .with_module(wallet.id)
                    .fetch_consensus_block_count()
                    .await?;
                if count >= target {
                    Ok(CliOutput::WaitBlockCount { reached: count })
                } else {
                    info!(target: LOG_CLIENT, current=count, target, "Block count not reached");
                    Err(format_err!("target not reached"))
                }
            },
        )
        .await
        .map_err_cli()
    }

    /// Keep the client alive while giving background networking a chance to
    /// start.
    pub(super) async fn wait_with_networking(
        &self,
        cli: &Opts,
        seconds: Option<f32>,
    ) -> CliOutputResult {
        let client = self.client_open(cli).await?;
        // Trigger a network call so background work can make progress while waiting.
        client
            .task_group()
            .spawn_cancellable("fedimint-cli dev wait: init networking", {
                let client = client.clone();
                async move {
                    let _ = client.api().session_count().await;
                }
            });
        if let Some(secs) = seconds {
            runtime::sleep(Duration::from_secs_f32(secs)).await;
        } else {
            pending::<()>().await;
        }
        Ok(CliOutput::Raw(serde_json::Value::Null))
    }
}
