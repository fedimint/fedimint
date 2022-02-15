use crate::api::{ApiError, FederationApi};
use crate::ln::{LnClient, LnClientError};
use crate::mint::{MintClient, MintClientError};
use crate::{api, OwnedClientContext};
use minimint::config::ClientConfig;
use minimint::modules::ln::contracts::{outgoing, ContractId};
use minimint::transaction::{agg_sign, Input, Output, Transaction, TransactionItem};
use minimint_api::db::batch::DbBatch;
use minimint_api::db::Database;
use minimint_api::{OutPoint, PeerId};
use rand::{CryptoRng, RngCore};
use thiserror::Error;

pub struct GatewayClient {
    context: OwnedClientContext<GatewayClientConfig>,
}

pub struct GatewayClientConfig {
    common: ClientConfig,
    redeem_key: secp256k1_zkp::schnorrsig::KeyPair,
}

impl GatewayClient {
    pub fn new(cfg: GatewayClientConfig, db: Box<dyn Database>) -> Self {
        let api = api::HttpFederationApi::new(
            cfg.common
                .api_endpoints
                .iter()
                .enumerate()
                .map(|(id, url)| {
                    let peer_id = PeerId::from(id as u16); // FIXME: potentially wrong, currently works imo
                    let url = url.parse().expect("Invalid URL in config");
                    (peer_id, url)
                })
                .collect(),
        );
        Self::new_with_api(cfg, db, Box::new(api))
    }

    pub fn new_with_api(
        config: GatewayClientConfig,
        db: Box<dyn Database>,
        api: Box<dyn FederationApi>,
    ) -> GatewayClient {
        GatewayClient {
            context: OwnedClientContext {
                config,
                db,
                api,
                secp: secp256k1_zkp::Secp256k1::new(),
            },
        }
    }

    fn ln_client(&self) -> LnClient {
        LnClient {
            context: self.context.borrow_with_module_config(|cfg| &cfg.common.ln),
        }
    }

    fn mint_client(&self) -> MintClient {
        MintClient {
            context: self
                .context
                .borrow_with_module_config(|cfg| &cfg.common.mint),
        }
    }

    /// Claim an outgoing contract after acquiring the preimage by paying the associated invoice and
    /// initiates e-cash issuances to receive the bitcoin from the contract (these still need to be
    /// fetched later to finalize them).
    ///
    /// Callers need to make sure that the contract can still be claimed by the gateway and has not
    /// timed out yet. Otherwise the transaction will fail.
    pub async fn claim_outgoing_contract(
        &self,
        contract_id: ContractId,
        preimage: outgoing::Preimage,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<OutPoint> {
        let contract = self.ln_client().get_outgoing_contract(contract_id).await?;
        let input = Input::LN(contract.claim(preimage));

        let (finalization_data, mint_output) = self
            .mint_client()
            .create_coin_output(input.amount(), &mut rng);
        let output = Output::Mint(mint_output);

        let inputs = vec![input];
        let outputs = vec![output];
        let txid = Transaction::tx_hash_from_parts(&inputs, &outputs);
        let signature = agg_sign(
            &[self.context.config.redeem_key],
            txid.as_hash(),
            &self.context.secp,
            &mut rng,
        );

        let out_point = OutPoint { txid, out_idx: 0 };
        let mut batch = DbBatch::new();
        self.mint_client().save_coin_finalization_data(
            batch.transaction(),
            out_point,
            finalization_data,
        );
        self.context.db.apply_batch(batch).expect("DB error");

        let transaction = Transaction {
            inputs,
            outputs,
            signature: Some(signature),
        };

        self.context.api.submit_transaction(transaction).await?;

        Ok(out_point)
    }

    /// Tries to fetch e-cash tokens from a certain out point. An error may just mean having queried
    /// the federation too early. Use [`MintClientError::is_retryable_fetch_coins`] to determine
    /// if the operation should be retried at a later time.
    pub async fn fetch_coins<'a>(
        &self,
        outpoint: OutPoint,
    ) -> std::result::Result<(), MintClientError> {
        let mut batch = DbBatch::new();
        self.mint_client()
            .fetch_coins(batch.transaction(), outpoint)
            .await?;
        self.context.db.apply_batch(batch).expect("DB error");
        Ok(())
    }
}

type Result<T> = std::result::Result<T, GatewayClientError>;

#[derive(Error, Debug)]
pub enum GatewayClientError {
    #[error("Error querying federation: {0}")]
    MintApiError(ApiError),
    #[error("Mint client error: {0}")]
    MintClientError(MintClientError),
    #[error("Lightning client error: {0}")]
    LnClientError(LnClientError),
}

impl From<LnClientError> for GatewayClientError {
    fn from(e: LnClientError) -> Self {
        GatewayClientError::LnClientError(e)
    }
}

impl From<ApiError> for GatewayClientError {
    fn from(e: ApiError) -> Self {
        GatewayClientError::MintApiError(e)
    }
}
