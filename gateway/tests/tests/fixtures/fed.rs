use async_trait::async_trait;
use bitcoin::{secp256k1, Address};
use fedimint_api::{backup::SignedBackupRequest, TransactionId};
use fedimint_core::{
    epoch::EpochHistory,
    modules::{
        ln::{
            contracts::{incoming::IncomingContractOffer, ContractId},
            ContractAccount, LightningGateway,
        },
        mint::db::ECashUserBackupSnapshot,
        wallet::PegOutFees,
    },
    outcome::TransactionStatus,
    transaction::legacy::Transaction as LegacyTransaction,
};
use mint_client::api::{ApiError, IFederationApi};
use tokio::sync::Mutex;

#[derive(Debug)]
pub struct MockApi {
    gateway: Mutex<Option<LightningGateway>>,
}

impl MockApi {
    pub fn new() -> Self {
        Self {
            gateway: Mutex::new(None),
        }
    }
}

#[async_trait]
impl IFederationApi for MockApi {
    async fn fetch_tx_outcome(&self, _tx: TransactionId) -> Result<TransactionStatus, ApiError> {
        unimplemented!()
    }

    async fn submit_transaction(&self, _tx: LegacyTransaction) -> Result<TransactionId, ApiError> {
        unimplemented!()
    }

    async fn fetch_contract(&self, _contract: ContractId) -> Result<ContractAccount, ApiError> {
        unimplemented!()
    }

    async fn fetch_consensus_block_height(&self) -> Result<u64, ApiError> {
        unimplemented!()
    }

    async fn fetch_offer(
        &self,
        _payment_hash: bitcoin::hashes::sha256::Hash,
    ) -> Result<IncomingContractOffer, ApiError> {
        unimplemented!();
    }

    async fn fetch_peg_out_fees(
        &self,
        _address: &Address,
        _amount: &bitcoin::Amount,
    ) -> Result<Option<PegOutFees>, ApiError> {
        unimplemented!();
    }

    async fn fetch_gateways(&self) -> Result<Vec<LightningGateway>, ApiError> {
        Ok(self
            .gateway
            .lock()
            .await
            .clone()
            .into_iter()
            .collect::<Vec<LightningGateway>>())
    }

    async fn register_gateway(&self, gateway: LightningGateway) -> Result<(), ApiError> {
        *self.gateway.lock().await = Some(gateway);
        Ok(())
    }

    async fn fetch_epoch_history(
        &self,
        _epoch: u64,
        _pk: threshold_crypto::PublicKey,
    ) -> Result<EpochHistory, ApiError> {
        unimplemented!()
    }

    async fn fetch_last_epoch(&self) -> Result<u64, ApiError> {
        unimplemented!()
    }

    async fn offer_exists(
        &self,
        _payment_hash: bitcoin::hashes::sha256::Hash,
    ) -> Result<bool, ApiError> {
        unimplemented!()
    }

    async fn upload_ecash_backup(&self, _request: &SignedBackupRequest) -> Result<(), ApiError> {
        unimplemented!()
    }

    async fn download_ecash_backup(
        &self,
        _id: &secp256k1::XOnlyPublicKey,
    ) -> Result<Vec<ECashUserBackupSnapshot>, ApiError> {
        unimplemented!()
    }
}
