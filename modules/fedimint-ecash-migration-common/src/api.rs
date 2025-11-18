use fedimint_core::encoding::Encodable;
use fedimint_core::{Amount, Tiered};
use fedimint_mint_common::Nonce;
use serde::{Deserialize, Serialize};
use tbs::AggregatePublicKey;

use crate::{KeySetHash, SpendBookHash, TransferId};

// API endpoint paths
pub const GET_TRANSFER_ID_ENDPOINT: &str = "get_transfer_id";
pub const UPLOAD_KEY_SET_ENDPOINT: &str = "upload_key_set";
pub const UPLOAD_SPEND_BOOK_BATCH_ENDPOINT: &str = "upload_spend_book_batch";
pub const GET_UPLOADED_SPEND_BOOK_ENTRIES_ENDPOINT: &str = "get_uploaded_spend_book_entries";
pub const REQUEST_ACTIVATION_ENDPOINT: &str = "request_activation";
pub const GET_TRANSFER_STATUS_ENDPOINT: &str = "get_transfer_status";

/// API: Request to upload a key set
#[derive(Debug, Clone, Serialize, Deserialize, Encodable)]
pub struct UploadKeySetRequest {
    pub transfer_id: TransferId,
    pub tier_keys: Tiered<AggregatePublicKey>,
}

/// API: Request to upload a batch of spend book entries
#[derive(Debug, Clone, Serialize, Deserialize, Encodable)]
pub struct UploadSpendBookBatchRequest {
    pub transfer_id: TransferId,
    pub entries: Vec<Nonce>,
}

/// API: Response from uploading spend book batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSpendBookBatchResponse {
    pub new_entries: u64,
    pub total_entries_uploaded: u64,
}

/// API: Request to activate redemption
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestActivationRequest {
    pub transfer_id: TransferId,
    pub auth_hmac: String,
}

/// API: Request to get transfer status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetTransferStatusRequest {
    pub transfer_id: TransferId,
}

/// API: Response with transfer status
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct GetTransferStatusResponse {
    pub is_active: bool,
    pub spend_book_hash: SpendBookHash,
    pub key_set_hash: KeySetHash,
    pub total_entries: u64,
    pub total_amount: Amount,
    pub redeemed_amount: Amount,
}
