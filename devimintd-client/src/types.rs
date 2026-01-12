use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteCodeResponse {
    pub invite_code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateEcashRequest {
    pub amount_msats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateEcashResponse {
    pub ecash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiveEcashRequest {
    pub ecash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendBitcoinRequest {
    pub address: String,
    pub amount_sats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendBitcoinResponse {
    pub txid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MineBlocksRequest {
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinAddressResponse {
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollTransactionRequest {
    pub txid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollTransactionResponse {
    pub hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetDepositFeesResponse {
    pub msats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInvoiceRequest {
    pub amount_msats: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LndInvoiceResponse {
    pub invoice: String,
    pub payment_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayInvoiceRequest {
    pub invoice: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaitInvoiceRequest {
    pub payment_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LndPubkeyResponse {
    pub pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayInvoiceResponse {
    pub invoice: String,
    pub payment_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecurringdUrlResponse {
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
