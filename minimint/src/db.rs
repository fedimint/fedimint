use database::{
    check_format, DatabaseKey, DatabaseKeyPrefix, DatabaseValue, DecodingError,
    SerializableDatabaseValue,
};
use mint_api::{BitcoinHash, TransactionId};
use serde::Serialize;
use std::fmt::Debug;

pub const DB_PREFIX_CONSENSUS_ITEM: u8 = 0x01;
pub const DB_PREFIX_ACCEPTED_TRANSACTION: u8 = 0x03;

#[derive(Debug)]
pub struct ConsensusItemsKeyPrefix;

#[derive(Debug)]
pub struct ConsensusItemKey(pub TransactionId);

#[derive(Debug, Serialize)]
pub struct AcceptedTransactionKey(pub TransactionId);

#[derive(Debug)]
pub struct DummyValue;

impl DatabaseKeyPrefix for ConsensusItemsKeyPrefix {
    fn to_bytes(&self) -> Vec<u8> {
        (&[DB_PREFIX_CONSENSUS_ITEM][..]).into()
    }
}

impl DatabaseKeyPrefix for ConsensusItemKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![DB_PREFIX_CONSENSUS_ITEM];
        bytes.extend_from_slice(&self.0[..]);
        bytes
    }
}

impl DatabaseKey for ConsensusItemKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        let data = check_format(data, DB_PREFIX_CONSENSUS_ITEM, 32)?;
        Ok(ConsensusItemKey(
            TransactionId::from_slice(data).expect("len checked above"),
        ))
    }
}

impl DatabaseKeyPrefix for AcceptedTransactionKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![DB_PREFIX_ACCEPTED_TRANSACTION];
        bytes.extend_from_slice(&self.0[..]);
        bytes
    }
}

impl DatabaseKey for AcceptedTransactionKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        Ok(AcceptedTransactionKey(
            TransactionId::from_slice(check_format(data, DB_PREFIX_ACCEPTED_TRANSACTION, 32)?)
                .unwrap(),
        ))
    }
}

impl SerializableDatabaseValue for DummyValue {
    fn to_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

impl DatabaseValue for DummyValue {
    fn from_bytes(_data: &[u8]) -> Result<Self, DecodingError> {
        Ok(DummyValue)
    }
}
