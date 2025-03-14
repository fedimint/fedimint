pub mod api;

use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::time::SystemTime;

use bitcoin::hashes::sha256;
use fedimint_core::BitcoinHash;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::{Keypair, PublicKey};
use fedimint_core::util::SafeUrl;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(
    Debug,
    Clone,
    Copy,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Encodable,
    Decodable,
    Serialize,
    Deserialize,
)]
pub struct PaymentCodeRootKey(pub PublicKey);

#[derive(
    Debug,
    Clone,
    Copy,
    PartialOrd,
    Eq,
    PartialEq,
    Hash,
    Encodable,
    Decodable,
    Serialize,
    Deserialize,
)]
pub struct PaymentCodeId(sha256::Hash);

impl PaymentCodeRootKey {
    pub fn to_payment_code_id(&self) -> PaymentCodeId {
        PaymentCodeId(sha256::Hash::hash(&self.0.serialize()))
    }
}

impl Display for PaymentCodeId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for PaymentCodeId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(sha256::Hash::from_str(s)?))
    }
}

impl Display for PaymentCodeRootKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for PaymentCodeRootKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(PublicKey::from_str(s)?))
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    PartialOrd,
    Hash,
    Encodable,
    Decodable,
    Serialize,
    Deserialize,
)]
pub enum RecurringPaymentProtocol {
    LNURL,
    BOLT12,
}

#[derive(Debug, Error)]
pub enum RecurringPaymentError {
    #[error("Unsupported protocol: {0:?}")]
    UnsupportedProtocol(RecurringPaymentProtocol),
    #[error("Unknown federation ID: {0}")]
    UnknownFederationId(FederationId),
    #[error("Unknown payment code: {0:?}")]
    UnknownPaymentCode(PaymentCodeId),
    #[error("No compatible lightning module found")]
    NoLightningModuleFound,
    #[error("No gateway found")]
    NoGatewayFound,
    #[error("Payment code already exists with different settings: {0:?}")]
    PaymentCodeAlreadyExists(PaymentCodeRootKey),
    #[error("Federation already registered: {0}")]
    FederationAlreadyRegistered(FederationId),
    #[error("Error joining federation: {0}")]
    JoiningFederationFailed(anyhow::Error),
    #[error("Error registering with recurring payment service: {0}")]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct RecurringPaymentCodeEntry {
    pub protocol: RecurringPaymentProtocol,
    pub root_keypair: Keypair,
    pub code: String,
    pub recurringd_api: SafeUrl,
    pub last_derivation_index: u64,
    pub creation_time: SystemTime,
}
