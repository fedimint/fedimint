use crate::consensus::ConsensusItem;
use crate::net::api::ClientRequest;
use database::{
    DatabaseKey, DatabaseKeyPrefix, DatabaseValue, DecodingError, SerializableDatabaseValue,
};
use mint_api::BitcoinHash;
use mint_api::{TransactionId, TxId};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::borrow::Cow;
use std::fmt::Debug;

pub const DB_PREFIX_CONSENSUS_ITEM: u8 = 0x01;
pub const DB_PREFIX_PARTIAL_SIG: u8 = 0x02;
pub const DB_PREFIX_FINALIZED_SIG: u8 = 0x03;

#[derive(Debug)]
pub struct BincodeSerialized<'a, T: Clone>(Cow<'a, T>);

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

impl<'a, T: Clone> BincodeSerialized<'a, T> {
    pub fn borrowed(obj: &'a T) -> BincodeSerialized<'a, T> {
        BincodeSerialized(Cow::Borrowed(obj))
    }

    pub fn owned(obj: T) -> BincodeSerialized<'static, T> {
        BincodeSerialized(Cow::Owned(obj))
    }

    pub fn into_owned(self) -> T {
        self.0.into_owned()
    }
}

impl<'a, T: Serialize + Debug + Clone> SerializableDatabaseValue for BincodeSerialized<'a, T> {
    fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.0)
            .expect("Serialization error")
            .into()
    }
}

impl<'a, T: Serialize + Debug + DeserializeOwned + Clone> DatabaseValue
    for BincodeSerialized<'a, T>
{
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        Ok(BincodeSerialized(
            bincode::deserialize(&data).map_err(|e| DecodingError(e.into()))?,
        ))
    }
}

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
            ConsensusItem::ClientRequest(ClientRequest::PegOut(_)) => {
                unimplemented!()
            }
            ConsensusItem::PartiallySignedRequest(id, _) => *id,
        };

        bytes.extend_from_slice(&issuance_id[..]);
        bincode::serialize_into(&mut bytes, &self).unwrap(); // TODO: use own encoding
        bytes.into()
    }
}

impl DatabaseKey for ConsensusItem {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        if data.len() < 33 {
            return Err(DecodingError("Too short".into()));
        }

        if data[0] != DB_PREFIX_CONSENSUS_ITEM {
            return Err(DecodingError("Wrong type".into()));
        }

        // skip 8 bytes that are the id

        bincode::deserialize(&data[33..]).map_err(|e| DecodingError(e.into()))
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
        if data.len() != 35 {
            return Err(DecodingError(
                format!("Expected 35 bytes, got {}", data.len()).into(),
            ));
        }

        if data[0] != DB_PREFIX_PARTIAL_SIG {
            return Err(DecodingError(
                "Expected partial sig, got something else".into(),
            ));
        }

        let request_id = TransactionId::from_slice(&data[1..33]).unwrap();

        let mut peer_id_bytes = [0u8; 2];
        peer_id_bytes.copy_from_slice(&data[33..]);
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
        if data.len() != 33 {
            return Err(DecodingError("Too short".into()));
        }

        if data[0] != DB_PREFIX_FINALIZED_SIG {
            return Err(DecodingError(
                "Expected finalized sig, got something else".into(),
            ));
        }

        Ok(FinalizedSignatureKey {
            issuance_id: TransactionId::from_slice(&data[1..]).unwrap(),
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
