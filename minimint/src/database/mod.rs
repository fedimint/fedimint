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
pub const DB_PREFIX_PARTIAL_SIG: u8 = 0x02;
pub const DB_PREFIX_TX_STATUS: u8 = 0x03;
pub const DB_PREFIX_TX_OUTPUT_OUTCOME: u8 = 0x04;

#[derive(Debug)]
pub struct AllConsensusItemsKeyPrefix;

#[derive(Debug)]
pub struct ConsensusItemKeyPrefix(pub TransactionId);

#[derive(Debug, Serialize)]
pub struct PartialSignatureKey {
    pub request_id: (TransactionId, usize), // tx + output idx
    pub peer_id: u16,
}

#[derive(Debug)]
pub struct AllPartialSignaturesKey;

#[derive(Debug, Serialize)]
pub struct TransactionStatusKey(pub TransactionId);

/// Transaction id and output index identifying an output outcome
#[derive(Debug, Serialize)]
pub struct TransactionOutputOutcomeKey(pub TransactionId, pub usize);

#[derive(Debug, Serialize)]
pub struct TransactionOutputOutcomeKeyPrefix {
    pub tx_hash: TransactionId,
}

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

impl DatabaseKeyPrefix for PartialSignatureKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(41);
        bytes.push(DB_PREFIX_PARTIAL_SIG);
        bytes.extend_from_slice(&self.request_id.0[..]);
        bytes.extend_from_slice(&self.request_id.1.to_be_bytes()[..]);
        bytes.extend_from_slice(&self.peer_id.to_be_bytes()[..]);
        bytes.into()
    }
}

impl DatabaseKey for PartialSignatureKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        let data = check_format(data, DB_PREFIX_PARTIAL_SIG, 42)?;

        let tx_hash = TransactionId::from_slice(&data[0..32]).unwrap();

        let mut out_idx_bytes = [0u8; 8];
        out_idx_bytes.copy_from_slice(&data[32..40]);
        let out_idx = usize::from_be_bytes(out_idx_bytes);

        let mut peer_id_bytes = [0u8; 2];
        peer_id_bytes.copy_from_slice(&data[40..]);
        let peer_id = u16::from_be_bytes(peer_id_bytes);

        Ok(PartialSignatureKey {
            request_id: (tx_hash, out_idx),
            peer_id,
        })
    }
}

impl DatabaseKeyPrefix for AllPartialSignaturesKey {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_PARTIAL_SIG]
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

impl DatabaseKeyPrefix for TransactionOutputOutcomeKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![DB_PREFIX_TX_OUTPUT_OUTCOME];
        bytes.extend_from_slice(&self.0[..]);
        bytes.extend_from_slice(&self.1.to_le_bytes());
        bytes
    }
}

impl DatabaseKey for TransactionOutputOutcomeKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        let data = check_format(data, DB_PREFIX_TX_OUTPUT_OUTCOME, 40)?;
        Ok(TransactionOutputOutcomeKey {
            0: TransactionId::from_slice(&data[..32]).unwrap(),
            1: usize::from_le_bytes(data[32..40].try_into().unwrap()),
        })
    }
}

impl DatabaseKeyPrefix for TransactionOutputOutcomeKeyPrefix {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![DB_PREFIX_TX_OUTPUT_OUTCOME];
        bytes.extend_from_slice(&self.tx_hash[..]);
        bytes
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

    let outputs = db
        .find_by_prefix::<_, TransactionOutputOutcomeKey, BincodeSerialized<_>>(
            &TransactionOutputOutcomeKeyPrefix { tx_hash },
        )
        .map(|res| {
            let (key, value) = res.expect("DB error");
            (key.1, value.into_owned())
        })
        .collect();

    Ok(Some(mint_api::outcome::TransactionOutcome {
        tx_hash,
        status,
        outputs,
    }))
}
