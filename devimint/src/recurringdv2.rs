use std::ops::ControlFlow;

use anyhow::Result;
use fedimint_core::task::sleep;
use fedimint_core::util::SafeUrl;
use reqwest::get;
use tracing::info;

use crate::cmd;
use crate::util::{ProcessHandle, ProcessManager, poll};

#[derive(Clone)]
pub struct Recurringdv2 {
    pub(crate) process: ProcessHandle,
    pub addr: String,
    pub api_url: SafeUrl,
}

impl Recurringdv2 {
    pub async fn new(process_mgr: &ProcessManager) -> Result<Self> {
        let port = process_mgr.globals.FM_PORT_RECURRINGDV2;
        let bind_address = format!("127.0.0.1:{port}");
        let api_url = SafeUrl::parse(&format!("http://{bind_address}/")).expect("Valid URL");

        let process = process_mgr
            .spawn_daemon(
                "recurringdv2",
                cmd!("fedimint-recurringdv2", "--bind-api", bind_address.clone()),
            )
            .await?;

        let recurringdv2 = Self {
            process,
            addr: bind_address,
            api_url,
        };

        poll("waiting for recurringdv2 to be ready", || async {
            match get(format!("http://{}", recurringdv2.addr)).await {
                Ok(response) if response.status().is_success() => Ok(()),
                _ => {
                    sleep(tokio::time::Duration::from_millis(100)).await;
                    Err(ControlFlow::Continue(anyhow::anyhow!(
                        "recurringdv2 not ready yet"
                    )))
                }
            }
        })
        .await?;

        info!("Recurringdv2 started at {}", recurringdv2.addr);
        Ok(recurringdv2)
    }

    pub async fn terminate(self) -> Result<()> {
        self.process.terminate().await
    }

    pub fn api_url(&self) -> SafeUrl {
        self.api_url.clone()
    }
}
