pub mod tests;
mod types;

use anyhow::Result;
use devimint::federation::Client;
use tracing::info;
pub use types::*;

/// Typed client for the devimintd server API.
///
/// This client provides typed access to devimint operations like generating
/// ecash, sending bitcoin, creating lightning invoices, etc.
#[derive(Clone)]
pub struct DevimintdClient {
    base_url: String,
    devfed_id: String,
    client: reqwest::Client,
}

impl DevimintdClient {
    pub fn new(devfed_id: impl Into<String>) -> Self {
        #[cfg(not(target_family = "wasm"))]
        let base_url =
            std::env::var("DEVIMINTD_URL").expect("DEVIMINTD_URL environment variable not set");
        #[cfg(target_family = "wasm")]
        let base_url = "http://127.0.0.1:29205".to_string();
        Self {
            base_url,
            devfed_id: devfed_id.into(),
            client: reqwest::Client::new(),
        }
    }

    pub fn shared() -> Self {
        Self::new("shared")
    }

    pub fn dedicated() -> Self {
        let this = Self::new(uuid::Uuid::new_v4().to_string());
        // this will stop when tokio runtime stops
        fedimint_core::runtime::spawn("keep alive", this.clone().keep_alive_loop());
        this
    }

    /// Get the federation invite code.
    pub async fn invite_code(&self) -> Result<String> {
        let resp: InviteCodeResponse = self
            .client
            .get(format!("{}/{}/invite_code", self.base_url, self.devfed_id))
            .send()
            .await?
            .better_error_for_status()
            .await?
            .json()
            .await?;
        Ok(resp.invite_code)
    }

    /// Generate ecash notes of the given amount.
    pub async fn generate_ecash(&self, amount_msats: u64) -> Result<String> {
        let resp: GenerateEcashResponse = self
            .client
            .post(format!(
                "{}/{}/ecash/generate",
                self.base_url, self.devfed_id
            ))
            .json(&GenerateEcashRequest { amount_msats })
            .send()
            .await?
            .better_error_for_status()
            .await?
            .json()
            .await?;
        Ok(resp.ecash)
    }

    /// Receive/reissue ecash notes.
    pub async fn receive_ecash(&self, ecash: String) -> Result<()> {
        self.client
            .post(format!(
                "{}/{}/ecash/receive",
                self.base_url, self.devfed_id
            ))
            .json(&ReceiveEcashRequest { ecash })
            .send()
            .await?
            .better_error_for_status()
            .await?;
        Ok(())
    }

    /// Send bitcoin to an address and mine blocks.
    pub async fn send_bitcoin(&self, address: &str, amount_sats: u64) -> Result<String> {
        let resp: SendBitcoinResponse = self
            .client
            .post(format!("{}/{}/bitcoin/send", self.base_url, self.devfed_id))
            .json(&SendBitcoinRequest {
                address: address.to_string(),
                amount_sats,
            })
            .send()
            .await?
            .better_error_for_status()
            .await?
            .json()
            .await?;
        Ok(resp.txid)
    }

    /// Mine the specified number of blocks.
    pub async fn mine_blocks(&self, count: u64) -> Result<()> {
        self.client
            .post(format!("{}/{}/bitcoin/mine", self.base_url, self.devfed_id))
            .json(&MineBlocksRequest { count })
            .send()
            .await?
            .better_error_for_status()
            .await?;
        Ok(())
    }

    /// Get a new bitcoin address.
    pub async fn bitcoin_address(&self) -> Result<String> {
        let resp: BitcoinAddressResponse = self
            .client
            .get(format!(
                "{}/{}/bitcoin/address",
                self.base_url, self.devfed_id
            ))
            .send()
            .await?
            .better_error_for_status()
            .await?
            .json()
            .await?;
        Ok(resp.address)
    }

    /// Get a bitcoin transaction hex.
    pub async fn poll_bitcoin_transaction(&self, txid: &str) -> Result<String> {
        let resp: PollTransactionResponse = self
            .client
            .post(format!(
                "{}/{}/bitcoin/transaction",
                self.base_url, self.devfed_id
            ))
            .json(&PollTransactionRequest {
                txid: txid.to_string(),
            })
            .send()
            .await?
            .better_error_for_status()
            .await?
            .json()
            .await?;
        Ok(resp.hex)
    }

    /// Get federation deposit fees.
    pub async fn deposit_fees(&self) -> Result<u64> {
        let resp: GetDepositFeesResponse = self
            .client
            .get(format!("{}/{}/deposit_fees", self.base_url, self.devfed_id))
            .send()
            .await?
            .better_error_for_status()
            .await?
            .json()
            .await?;
        Ok(resp.msats)
    }

    /// Create an LND invoice.
    pub async fn create_lnd_invoice(&self, amount_msats: u64) -> Result<(String, Vec<u8>)> {
        let resp: LndInvoiceResponse = self
            .client
            .post(format!(
                "{}/{}/lightning/invoice",
                self.base_url, self.devfed_id
            ))
            .json(&CreateInvoiceRequest { amount_msats })
            .send()
            .await?
            .better_error_for_status()
            .await?
            .json()
            .await?;
        Ok((resp.invoice, resp.payment_hash))
    }

    /// Pay an LND invoice.
    pub async fn pay_lnd_invoice(&self, invoice: &str) -> Result<()> {
        self.client
            .post(format!(
                "{}/{}/lightning/pay",
                self.base_url, self.devfed_id
            ))
            .json(&PayInvoiceRequest {
                invoice: invoice.to_string(),
            })
            .send()
            .await?
            .better_error_for_status()
            .await?;
        Ok(())
    }

    /// Wait for an LND invoice to be paid.
    pub async fn wait_lnd_invoice(&self, payment_hash: &[u8]) -> Result<()> {
        self.client
            .post(format!(
                "{}/{}/lightning/wait",
                self.base_url, self.devfed_id
            ))
            .json(&WaitInvoiceRequest {
                payment_hash: payment_hash.to_vec(),
            })
            .send()
            .await?
            .better_error_for_status()
            .await?;
        Ok(())
    }

    /// Get the LND node pubkey.
    pub async fn lnd_pubkey(&self) -> Result<String> {
        let resp: LndPubkeyResponse = self
            .client
            .get(format!(
                "{}/{}/lightning/pubkey",
                self.base_url, self.devfed_id
            ))
            .send()
            .await?
            .better_error_for_status()
            .await?
            .json()
            .await?;
        Ok(resp.pubkey)
    }

    /// Create an invoice via the LDK gateway.
    pub async fn create_gateway_invoice(&self, amount_msats: u64) -> Result<(String, Vec<u8>)> {
        let resp: GatewayInvoiceResponse = self
            .client
            .post(format!(
                "{}/{}/gateway/invoice",
                self.base_url, self.devfed_id
            ))
            .json(&CreateInvoiceRequest { amount_msats })
            .send()
            .await?
            .better_error_for_status()
            .await?
            .json()
            .await?;
        Ok((resp.invoice, resp.payment_hash))
    }

    /// Wait for a gateway invoice to be paid.
    pub async fn wait_gateway_invoice(&self, payment_hash: &[u8]) -> Result<()> {
        self.client
            .post(format!("{}/{}/gateway/wait", self.base_url, self.devfed_id))
            .json(&WaitInvoiceRequest {
                payment_hash: payment_hash.to_vec(),
            })
            .send()
            .await?
            .better_error_for_status()
            .await?;
        Ok(())
    }

    /// Get the recurringd API URL.
    pub async fn recurringd_url(&self) -> Result<String> {
        let resp: RecurringdUrlResponse = self
            .client
            .get(format!(
                "{}/{}/recurringd/url",
                self.base_url, self.devfed_id
            ))
            .send()
            .await?
            .better_error_for_status()
            .await?
            .json()
            .await?;
        Ok(resp.url)
    }

    /// Terminate all federation servers.
    pub async fn terminate_all_fed_servers(&self) -> Result<()> {
        self.client
            .post(format!(
                "{}/{}/terminate_all_fed_servers",
                self.base_url, self.devfed_id
            ))
            .send()
            .await?
            .better_error_for_status()
            .await?;
        Ok(())
    }

    /// Send a keep-alive request to the server.
    async fn keep_alive(&self) -> Result<()> {
        self.client
            .post(format!("{}/{}/keep-alive", self.base_url, self.devfed_id))
            .send()
            .await?
            .better_error_for_status()
            .await?;
        Ok(())
    }

    /// Run a loop that sends a keep-alive request every 10 seconds.
    async fn keep_alive_loop(self) {
        loop {
            fedimint_core::task::sleep(std::time::Duration::from_secs(10)).await;
            if let Err(e) = self.keep_alive().await {
                tracing::warn!("Keep-alive failed: {e}");
            }
        }
    }

    pub async fn new_joined_client(&self, name: impl ToString) -> Result<Client> {
        let client = Client::create(name).await?;
        client.join_federation(self.invite_code().await?).await?;
        Ok(client)
    }

    pub async fn pegin_client_no_wait(&self, amount: u64, client: &Client) -> Result<String> {
        let deposit_fees_msat = self.deposit_fees().await?;
        assert_eq!(
            deposit_fees_msat % 1000,
            0,
            "Deposit fees expected to be whole sats in test suite"
        );
        let deposit_fees = deposit_fees_msat / 1000;
        info!(amount, deposit_fees, "Pegging-in client funds");

        let (address, operation_id) = client.get_deposit_addr().await?;

        self.send_bitcoin(&address, amount + deposit_fees).await?;
        self.mine_blocks(21).await?;

        Ok(operation_id)
    }

    pub async fn pegin_client(&self, amount: u64, client: &Client) -> Result<()> {
        let operation_id = self.pegin_client_no_wait(amount, client).await?;
        client.await_deposit(&operation_id).await?;
        Ok(())
    }
}

trait ResponseExt: Sized {
    async fn better_error_for_status(self) -> anyhow::Result<Self>;
}

impl ResponseExt for reqwest::Response {
    async fn better_error_for_status(self) -> anyhow::Result<Self> {
        let status = self.status();
        if status.is_client_error() || status.is_server_error() {
            anyhow::bail!("Status {status}: {body}", body = self.text().await?)
        } else {
            Ok(self)
        }
    }
}
