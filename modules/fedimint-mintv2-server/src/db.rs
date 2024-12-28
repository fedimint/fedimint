use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::{impl_db_lookup, impl_db_record, Amount};
use serde::Serialize;
use strum_macros::EnumIter;
use tbs::BlindedSignatureShare;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    NoteNonce = 0x10,
    BlindedSignatureShare = 0x13,
    MintAuditItem = 0x14,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct NonceKey(pub PublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct NonceKeyPrefix;

impl_db_record!(
    key = NonceKey,
    value = (),
    db_prefix = DbKeyPrefix::NoteNonce,
);
impl_db_lookup!(key = NonceKey, query_prefix = NonceKeyPrefix);

#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct BlindedSignatureShareKey(pub tbs::BlindedMessage);

#[derive(Debug, Encodable, Decodable)]
pub struct BlindedSignatureSharePrefix;

impl_db_record!(
    key = BlindedSignatureShareKey,
    value = BlindedSignatureShare,
    db_prefix = DbKeyPrefix::BlindedSignatureShare,
);
impl_db_lookup!(
    key = BlindedSignatureShareKey,
    query_prefix = BlindedSignatureSharePrefix
);

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct IssuanceCounterKey(pub Amount);

#[derive(Debug, Encodable, Decodable)]
pub struct IssuanceCounterPrefix;

impl_db_record!(
    key = IssuanceCounterKey,
    value = u64,
    db_prefix = DbKeyPrefix::MintAuditItem,
);
impl_db_lookup!(
    key = IssuanceCounterKey,
    query_prefix = IssuanceCounterPrefix
);
