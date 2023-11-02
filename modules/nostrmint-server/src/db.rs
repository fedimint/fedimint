use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, PeerId};
use nostrmint_common::{NostrmintNonceKeyPair, NostrmintSignatureShare, UnsignedEvent};
use serde::Serialize;

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum DbKeyPrefix {
    Nonce = 0x01,
    SignatureShare = 0x02,
    MessageNonceRequest = 0x03,
    MessageSignRequest = 0x04,
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct NostrmintNonceKey(pub UnsignedEvent, pub PeerId);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct NostrmintNonceKeyMessagePrefix(pub UnsignedEvent);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct NostrmintNonceKeyPrefix;

impl_db_record!(
    key = NostrmintNonceKey,
    value = NostrmintNonceKeyPair,
    db_prefix = DbKeyPrefix::Nonce
);

impl_db_lookup!(
    key = NostrmintNonceKey,
    query_prefix = NostrmintNonceKeyPrefix,
    query_prefix = NostrmintNonceKeyMessagePrefix
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct NostrmintSignatureShareKey(pub UnsignedEvent, pub PeerId);

impl_db_record!(
    key = NostrmintSignatureShareKey,
    value = NostrmintSignatureShare,
    db_prefix = DbKeyPrefix::SignatureShare
);

impl_db_lookup!(
    key = NostrmintSignatureShareKey,
    query_prefix = NostrmintSignatureShareKeyPrefix,
    query_prefix = NostrmintSignatureShareKeyMessagePrefix
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct NostrmintSignatureShareKeyMessagePrefix(pub UnsignedEvent);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct NostrmintSignatureShareKeyPrefix;

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct MessageNonceRequest;

impl_db_record!(
    key = MessageNonceRequest,
    value = UnsignedEvent,
    db_prefix = DbKeyPrefix::MessageNonceRequest
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct MessageSignRequest;

impl_db_record!(
    key = MessageSignRequest,
    value = UnsignedEvent,
    db_prefix = DbKeyPrefix::MessageSignRequest
);
