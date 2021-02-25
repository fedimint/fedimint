use crate::consensus::ConsensusItem;
use database::{DatabaseKey, DatabaseKeyPrefix, DatabaseValue, DecodingError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::borrow::Cow;
use std::fmt::Debug;

const DB_PREFIX_CONSENSUS_ITEM: u8 = 1;
const DB_PREFIX_PARTIAL_SIG: u8 = 2;

#[derive(Debug)]
pub struct BincodeSerialized<'a, T: Clone>(Cow<'a, T>);

#[derive(Debug)]
pub struct ConsensusItemKeyPrefix;

#[derive(Debug)]
pub struct PartialSignatureKey {
    pub request_id: u64,
    pub peer_id: u16,
}

#[derive(Debug)]
pub struct PartialSignaturesPrefixKey {
    pub request_id: u64,
}

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

impl<'a, T: Serialize + DeserializeOwned + Clone> DatabaseValue for BincodeSerialized<'a, T> {
    fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.0)
            .expect("Serialization error")
            .into()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        Ok(BincodeSerialized(
            bincode::deserialize(&data).map_err(|e| DecodingError(e.into()))?,
        ))
    }
}

impl DatabaseKeyPrefix for ConsensusItemKeyPrefix {
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
        // TODO: Distinguish key and value encoding
        if let Some(&typ) = data.first() {
            if typ != DB_PREFIX_CONSENSUS_ITEM {
                return Err(DecodingError("Wrong type".into()));
            }
        } else {
            return Err(DecodingError("No type field".into()));
        }

        bincode::deserialize(&data[1..]).map_err(|e| DecodingError(e.into()))
    }
}

impl DatabaseKeyPrefix for PartialSignatureKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(11);
        bytes.push(DB_PREFIX_PARTIAL_SIG);
        bytes.extend_from_slice(&self.request_id.to_be_bytes()[..]);
        bytes.extend_from_slice(&self.peer_id.to_be_bytes()[..]);
        bytes.into()
    }
}

impl DatabaseKey for PartialSignatureKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        if data.len() != 11 {
            return Err(DecodingError(
                "Expected 11 bytes, got something else".into(),
            ));
        }

        if data[0] != DB_PREFIX_PARTIAL_SIG {
            return Err(DecodingError(
                "Expected partial sig, got something else".into(),
            ));
        }

        let mut request_id_bytes = [0u8; 8];
        request_id_bytes.copy_from_slice(&data[1..9]);
        let request_id = u64::from_be_bytes(request_id_bytes);

        let mut peer_id_bytes = [0u8; 2];
        peer_id_bytes.copy_from_slice(&data[9..11]);
        let peer_id = u16::from_be_bytes(peer_id_bytes);

        Ok(PartialSignatureKey {
            request_id,
            peer_id,
        })
    }
}

impl DatabaseKeyPrefix for PartialSignaturesPrefixKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(9);
        bytes.push(DB_PREFIX_PARTIAL_SIG);
        bytes.extend_from_slice(&self.request_id.to_be_bytes()[..]);
        bytes.into()
    }
}
