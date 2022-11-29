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
        wallet::PegOutFees,
    },
    outcome::TransactionStatus,
    transaction::legacy::Transaction as LegacyTransaction,
};
use mint_client::api::{ApiError, IFederationApi};

#[derive(Debug)]
pub struct MockApi {}

impl MockApi {
    pub fn new() -> Self {
        Self {}
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
        unimplemented!()
    }

    async fn register_gateway(&self, _gateway: LightningGateway) -> Result<(), ApiError> {
        unimplemented!()
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
    ) -> Result<Vec<u8>, ApiError> {
        unimplemented!()
    }
}
