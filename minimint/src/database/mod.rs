use crate::consensus::ConsensusItem;
use database::{
    check_format, BincodeSerialized, Database, DatabaseError, DatabaseKey, DatabaseKeyPrefix,
    DatabaseValue, DecodingError, RawDatabase, SerializableDatabaseValue,
};
use mint_api::outcome::TransactionStatus;
use mint_api::{BitcoinHash, TransactionId};
use serde::Serialize;
use std::convert::TryInto;
use std::fmt::Debug;

pub const DB_PREFIX_CONSENSUS_ITEM: u8 = 0x01;
pub const DB_PREFIX_TX_STATUS: u8 = 0x03;

#[derive(Debug)]
pub struct AllConsensusItemsKeyPrefix;

#[derive(Debug)]
pub struct ConsensusItemKeyPrefix(pub TransactionId);

#[derive(Debug, Serialize)]
pub struct TransactionStatusKey(pub TransactionId);

#[derive(Debug)]
pub struct DummyValue;

impl DatabaseKeyPrefix for AllConsensusItemsKeyPrefix {
    fn to_bytes(&self) -> Vec<u8> {
        (&[DB_PREFIX_CONSENSUS_ITEM][..]).into()
    }
}

impl DatabaseKeyPrefix for ConsensusItem {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![DB_PREFIX_CONSENSUS_ITEM];
        bincode::serialize_into(&mut bytes, &self).unwrap(); // TODO: use own encoding
        bytes.into()
    }
}

impl DatabaseKey for ConsensusItem {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        if data.len() < 1 {
            return Err(DecodingError::wrong_length(1, data.len()));
        }

        if data[0] != DB_PREFIX_CONSENSUS_ITEM {
            return Err(DecodingError::wrong_prefix(
                DB_PREFIX_CONSENSUS_ITEM,
                data[0],
            ));
        }
        bincode::deserialize(&data[1..]).map_err(|e| DecodingError::other(e))
    }
}

impl DatabaseKeyPrefix for ConsensusItemKeyPrefix {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![DB_PREFIX_CONSENSUS_ITEM];
        bytes.extend_from_slice(&self.0[..]);
        bytes
    }
}

impl DatabaseKeyPrefix for TransactionStatusKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![DB_PREFIX_TX_STATUS];
        bytes.extend_from_slice(&self.0[..]);
        bytes
    }
}

impl DatabaseKey for TransactionStatusKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        Ok(TransactionStatusKey(
            TransactionId::from_slice(check_format(data, DB_PREFIX_TX_STATUS, 32)?).unwrap(),
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

pub fn load_tx_outcome(
    db: &dyn RawDatabase,
    tx_hash: TransactionId,
) -> Result<Option<mint_api::outcome::TransactionOutcome>, DatabaseError> {
    let status = match db
        .get_value::<_, BincodeSerialized<TransactionStatus>>(&TransactionStatusKey(tx_hash))?
    {
        Some(status) => status.into_owned(),
        None => return Ok(None),
    };

    // TODO: fetch output outcomes from respective modules, need to save whole tx for that
    unimplemented!();
}
