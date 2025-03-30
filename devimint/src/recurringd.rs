use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::PathBuf;

use anyhow::Result;
use fedimint_core::task::sleep;
use fedimint_core::util::SafeUrl;
use reqwest::get;
use tracing::info;
use {reqwest, serde_json};

use crate::cmd;
use crate::envs::{
    FM_RECURRING_API_ADDRESS_ENV, FM_RECURRING_API_BEARER_TOKEN_ENV, FM_RECURRING_BIND_ADDRESS_ENV,
    FM_RECURRING_DATA_DIR_ENV,
};
use crate::util::{ProcessHandle, ProcessManager, poll};

#[derive(Clone)]
pub struct Recurringd {
    pub(crate) process: ProcessHandle,
    pub addr: String,
    pub api_url: SafeUrl,
    pub log_path: PathBuf,
}

impl Recurringd {
    pub async fn new(process_mgr: &ProcessManager) -> Result<Self> {
        let test_dir = &process_mgr.globals.FM_TEST_DIR;
        let port = process_mgr.globals.FM_PORT_RECURRINGD;
        let bind_address = format!("127.0.0.1:{port}");
        let api_url = SafeUrl::parse(&format!("http://{bind_address}/")).expect("Valid URL");

        // Default bearer token for development
        let bearer_token = "devimint-recurring-token";

        let recurring_env: HashMap<String, String> = HashMap::from_iter([
            (
                FM_RECURRING_DATA_DIR_ENV.to_owned(),
                format!("{}/recurringd", test_dir.display()),
            ),
            (
                FM_RECURRING_BIND_ADDRESS_ENV.to_owned(),
                bind_address.clone(),
            ),
            (FM_RECURRING_API_ADDRESS_ENV.to_owned(), api_url.to_string()),
            (
                FM_RECURRING_API_BEARER_TOKEN_ENV.to_owned(),
                bearer_token.to_string(),
            ),
        ]);

        let process = process_mgr
            .spawn_daemon(
                "recurringd",
                cmd!("fedimint-recurringd").envs(recurring_env),
            )
            .await?;

        let log_path = process_mgr.globals.FM_LOGS_DIR.join("recurringd.log");

        let recurringd = Self {
            process,
            addr: bind_address,
            api_url,
            log_path,
        };

        // Poll to ensure the service is ready by checking the /federations endpoint
        poll("waiting for recurringd to be ready", || async {
            match get(format!("http://{}/lnv1/federations", recurringd.addr)).await {
                Ok(response) if response.status().is_success() => Ok(()),
                _ => {
                    sleep(tokio::time::Duration::from_millis(100)).await;
                    Err(ControlFlow::Continue(anyhow::anyhow!(
                        "recurringd not ready yet"
                    )))
                }
            }
        })
        .await?;

        info!("Recurringd started at {}", recurringd.addr);
        Ok(recurringd)
    }

    pub async fn terminate(self) -> Result<()> {
        self.process.terminate().await
    }

    // Add a federation to recurringd
    pub async fn add_federation(&self, invite_code: &str) -> Result<String> {
        let url = format!("http://{}/lnv1/federations", self.addr);
        let client = reqwest::Client::new();
        let response = client
            .put(&url)
            .header("Authorization", "Bearer devimint-recurring-token")
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "invite": invite_code }))
            .send()
            .await?;

        Ok(response.text().await?)
    }

    // List federations registered with recurringd
    pub async fn list_federations(&self) -> Result<String> {
        let url = format!("http://{}/lnv1/federations", self.addr);
        let client = reqwest::Client::new();
        let response = client
            .get(&url)
            .header("Authorization", "Bearer devimint-recurring-token")
            .send()
            .await?;

        Ok(response.text().await?)
    }

    pub fn api_url(&self) -> SafeUrl {
        self.api_url.clone()
    }
}
