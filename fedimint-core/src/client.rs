use async_trait::async_trait;
use bitcoin_hashes::sha256::Hash as Sha256Hash;
use crate::task::{RwLock, RwLockWriteGuard};
use crate::{NumPeers, OutPoint, PeerId, TransactionId};
// use crate::modules::ln::contracts::incoming::IncomingContractOffer;
// use crate::modules::ln::contracts::ContractId;
// use crate::modules::ln::{ContractAccount, LightningGateway};
// use crate::outcome::{TransactionStatus, TryIntoOutcome};
// use crate::transaction::Transaction;
// use crate::CoreError;
// use jsonrpsee_core::client::ClientT;
// use jsonrpsee_core::Error as JsonRpcError;
// use jsonrpsee_types::error::CallError as RpcCallError;
// use serde::{Deserialize, Serialize};

// use tracing::{error, info, instrument};
// use url::Url;

// #[cfg(target_os = "android")]
// use jsonrpsee_core::client::CertificateStore;
// #[cfg(not(target_family = "wasm"))]
// use jsonrpsee_ws_client::{WsClient, WsClientBuilder};

// #[cfg(target_family = "wasm")]
// use jsonrpsee_wasm_client::{Client as WsClient, WasmClientBuilder as WsClientBuilder};

// use crate::query::{
//     CurrentConsensus, EventuallyConsistent, QueryStep, QueryStrategy, Retry404, UnionResponses,
//     ValidHistory,
// };
use bitcoin::{Address, Amount};
// use crate::config::ClientConfig;
// use crate::epoch::EpochHistory;
// use crate::modules::wallet::PegOutFees;
use futures::stream::FuturesUnordered;

use futures::StreamExt;
use std::time::Duration;
use thiserror::Error;

use crate::module::ApiError;
// use threshold_crypto::PublicKey;

pub type Result<T> = std::result::Result<T, ApiError>;

#[cfg_attr(target_family = "wasm", async_trait(? Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait FederationApi: Send + Sync {
    /// Fetch the outcome of an entire transaction
    async fn fetch_tx_outcome(&self, tx: TransactionId) -> Result<TransactionStatus>;

    /// Submit a transaction to all federation members
    async fn submit_transaction(&self, tx: Transaction) -> Result<TransactionId>;

    async fn fetch_epoch_history(&self, epoch: u64, epoch_pk: PublicKey) -> Result<EpochHistory>;

    // TODO: more generic module API extensibility
    /// Fetch ln contract state
    async fn fetch_contract(&self, contract: ContractId) -> Result<ContractAccount>;

    /// Fetch preimage offer for incoming lightning payments
    async fn fetch_offer(&self, payment_hash: Sha256Hash) -> Result<IncomingContractOffer>;

    // TODO: find a better abstraction for all our API endpoints that allows different strategies and timeouts
    /// Checks if there exists an offer for a payment hash
    async fn offer_exists(&self, payment_hash: Sha256Hash) -> Result<bool>;

    /// Fetch the current consensus block height (trailing actual block height)
    async fn fetch_consensus_block_height(&self) -> Result<u64>;

    /// Fetch the expected peg-out fees given a peg-out tx
    async fn fetch_peg_out_fees(
        &self,
        address: &Address,
        amount: &Amount,
    ) -> Result<Option<PegOutFees>>;

    /// Fetch available lightning gateways (assumes gateways register with all peers)
    async fn fetch_gateways(&self) -> Result<Vec<LightningGateway>>;

    /// Register a gateway with the federation
    async fn register_gateway(&self, gateway: LightningGateway) -> Result<()>;
}
