use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

use crate::EscrowId;

pub const GET_CONTRACT_ENDPOINT: &str = "get_contract";
pub const GET_CLAIM_AMOUNT_ENDPOINT: &str = "get_claim_amount";
pub const LIST_CONTRACT_BY_KEY_ENDPOINT: &str = "list_contract_by_key";
pub const CONSENSUS_UNIX_TIME_ENDPOINT: &str = "consensus_unix_time";

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct GetContractParams {
    pub escrow_id: EscrowId,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct GetClaimAmount {
    pub escrow_id: EscrowId,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct ListContractParams {
    pub pubkey: PublicKey,
    pub federation_id: FederationId,
    pub limit: Option<u32>,
    pub last_seen: Option<EscrowId>,
}
