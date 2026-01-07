use fedimint_core::encoding::Encodable;
use fedimint_core::{Amount, Tiered};
use fedimint_mint_common::Nonce;
use serde::{Deserialize, Serialize};
use tbs::AggregatePublicKey;

use crate::merkle::{ChunkMerkleProof, MerkleRoot};
use crate::{KeySetHash, TransferId};

// API endpoint paths
pub const GET_TRANSFER_ID_ENDPOINT: &str = "get_transfer_id";
pub const UPLOAD_KEY_SET_ENDPOINT: &str = "upload_key_set";
pub const UPLOAD_SPEND_BOOK_BATCH_ENDPOINT: &str = "upload_spend_book_batch";
pub const GET_UPLOADED_SPEND_BOOK_ENTRIES_ENDPOINT: &str = "get_uploaded_spend_book_entries";
pub const GET_TRANSFER_STATUS_ENDPOINT: &str = "get_transfer_status";

/// API: Request to upload a key set
#[derive(Debug, Clone, Serialize, Deserialize, Encodable)]
pub struct UploadKeySetRequest {
    pub transfer_id: TransferId,
    pub tier_keys: Tiered<AggregatePublicKey>,
}

/// API: Request to upload a chunk of spend book entries with Merkle proof.
///
/// Each nonce is hashed individually as a leaf in the Merkle tree. Chunks are
/// power-of-2 sized groups of consecutive leaves. The server verifies that
/// the chunk's subtree root belongs to the pre-committed Merkle root using
/// the provided proof. The chunk entries are included within the proof.
#[derive(Debug, Clone, Serialize, Deserialize, Encodable)]
pub struct UploadSpendBookBatchRequest {
    /// The transfer to upload to
    pub transfer_id: TransferId,
    /// Merkle proof containing the chunk and path to the root
    pub merkle_proof: ChunkMerkleProof<Nonce>,
}

/// API: Response from uploading spend book batch
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadSpendBookBatchResponse {
    /// Number of new entries uploaded (may be less if some were duplicates)
    pub new_entries: u64,
    /// Total number of spend book entries uploaded so far
    pub total_uploaded: u64,
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
    pub spend_book_merkle_root: MerkleRoot<Nonce>,
    pub key_set_hash: KeySetHash,
    pub total_entries: u64,
    pub total_amount: Amount,
    pub redeemed_amount: Amount,
}
