use crate::consensus::ConsensusItem;
use crate::net::api::ClientRequest;
use database::{
    check_format, DatabaseKey, DatabaseKeyPrefix, DatabaseValue, DecodingError,
    SerializableDatabaseValue,
};
use mint_api::BitcoinHash;
use mint_api::{TransactionId, TxId};
use serde::Serialize;
use std::fmt::Debug;

pub const DB_PREFIX_CONSENSUS_ITEM: u8 = 0x01;
pub const DB_PREFIX_PARTIAL_SIG: u8 = 0x02;
pub const DB_PREFIX_FINALIZED_SIG: u8 = 0x03;

#[derive(Debug)]
pub struct AllConsensusItemsKeyPrefix;

#[derive(Debug)]
pub struct ConsensusItemKeyPrefix(pub TransactionId);

#[derive(Debug, Serialize)]
pub struct PartialSignatureKey {
    pub request_id: TransactionId,
    pub peer_id: u16,
}

#[derive(Debug)]
pub struct AllPartialSignaturesKey;

#[derive(Debug, Serialize)]
pub struct FinalizedSignatureKey {
    pub issuance_id: TransactionId,
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

        // TODO: maybe generalize id concept to all CIs
        let issuance_id = match self {
            ConsensusItem::ClientRequest(ClientRequest::PegIn(pi)) => pi.id(),
            ConsensusItem::ClientRequest(ClientRequest::Reissuance(re)) => re.id(),
            ConsensusItem::ClientRequest(ClientRequest::PegOut(po)) => po.id(),
            ConsensusItem::PartiallySignedRequest(id, _) => *id,
            // Wallet CIs are never written, we might try to remove them though
            ConsensusItem::Wallet(_) => TransactionId::default(),
        };

        bytes.extend_from_slice(&issuance_id[..]);
        bincode::serialize_into(&mut bytes, &self).unwrap(); // TODO: use own encoding
        bytes.into()
    }
}

impl DatabaseKey for ConsensusItem {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        if data.len() < 33 {
            return Err(DecodingError::wrong_length(33, data.len()));
        }

        if data[0] != DB_PREFIX_CONSENSUS_ITEM {
            return Err(DecodingError::wrong_prefix(
                DB_PREFIX_CONSENSUS_ITEM,
                data[0],
            ));
        }

        // skip 8 bytes that are the id

        bincode::deserialize(&data[33..]).map_err(|e| DecodingError::other(e))
    }
}

impl DatabaseKeyPrefix for PartialSignatureKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(41);
        bytes.push(DB_PREFIX_PARTIAL_SIG);
        bytes.extend_from_slice(&self.request_id[..]);
        bytes.extend_from_slice(&self.peer_id.to_be_bytes()[..]);
        bytes.into()
    }
}

impl DatabaseKey for PartialSignatureKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        let data = check_format(data, DB_PREFIX_PARTIAL_SIG, 34)?;

        let request_id = TransactionId::from_slice(&data[0..32]).unwrap();

        let mut peer_id_bytes = [0u8; 2];
        peer_id_bytes.copy_from_slice(&data[32..]);
        let peer_id = u16::from_be_bytes(peer_id_bytes);

        Ok(PartialSignatureKey {
            request_id,
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

impl DatabaseKeyPrefix for FinalizedSignatureKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![DB_PREFIX_FINALIZED_SIG];
        bytes.extend_from_slice(&self.issuance_id[..]);
        bytes
    }
}

impl DatabaseKey for FinalizedSignatureKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        Ok(FinalizedSignatureKey {
            issuance_id: TransactionId::from_slice(check_format(
                data,
                DB_PREFIX_FINALIZED_SIG,
                32,
            )?)
            .unwrap(),
        })
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
