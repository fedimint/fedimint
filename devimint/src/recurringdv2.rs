use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::PathBuf;

use anyhow::Result;
use fedimint_core::task::sleep;
use fedimint_core::util::SafeUrl;
use reqwest::get;
use tracing::info;

use crate::cmd;
use crate::envs::{FM_RECURRINGDV2_BASE_URL_ENV, FM_RECURRINGDV2_BIND_ADDRESS_ENV};
use crate::util::{ProcessHandle, ProcessManager, poll};

#[derive(Clone)]
pub struct RecurringdV2 {
    pub(crate) process: ProcessHandle,
    pub addr: String,
    pub base_url: SafeUrl,
    pub log_path: PathBuf,
}

impl RecurringdV2 {
    pub async fn new(process_mgr: &ProcessManager) -> Result<Self> {
        let port = process_mgr.globals.FM_PORT_RECURRINGDV2;
        let bind_address = format!("127.0.0.1:{port}");
        let base_url = SafeUrl::parse(&format!("http://{bind_address}/")).expect("Valid URL");

        let recurringdv2_env: HashMap<String, String> = HashMap::from_iter([
            (
                FM_RECURRINGDV2_BIND_ADDRESS_ENV.to_owned(),
                bind_address.clone(),
            ),
            (
                FM_RECURRINGDV2_BASE_URL_ENV.to_owned(),
                base_url.to_string(),
            ),
        ]);

        let process = process_mgr
            .spawn_daemon(
                "recurringdv2",
                cmd!("fedimint-recurringdv2")
                    .arg(&"--base-url")
                    .arg(&base_url.to_string())
                    .arg(&"--bind-address")
                    .arg(&bind_address)
                    .arg(&"--encryption-key")
                    .arg(&"01234567890123456789012345678901")
                    .envs(recurringdv2_env),
            )
            .await?;

        let log_path = process_mgr.globals.FM_LOGS_DIR.join("recurringdv2.log");

        let recurringdv2 = Self {
            process,
            addr: bind_address,
            base_url: base_url.clone(),
            log_path,
        };

        // Poll to ensure the service is ready by checking a simple endpoint
        poll("waiting for recurringdv2 to be ready", || async {
            // Since recurringdv2 is stateless and doesn't have a federations endpoint,
            // we just try to hit the base URL
            match get(format!("http://{}/", recurringdv2.addr)).await {
                Ok(response)
                    if response.status().is_client_error() || response.status().is_success() =>
                {
                    Ok(())
                }
                _ => {
                    sleep(tokio::time::Duration::from_millis(100)).await;
                    Err(ControlFlow::Continue(anyhow::anyhow!(
                        "recurringdv2 not ready yet"
                    )))
                }
            }
        })
        .await?;

        info!("RecurringdV2 started at {}", recurringdv2.addr);
        Ok(recurringdv2)
    }

    pub async fn terminate(self) -> Result<()> {
        self.process.terminate().await
    }

    pub fn base_url(&self) -> SafeUrl {
        self.base_url.clone()
    }
}
