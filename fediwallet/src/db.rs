use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash as BitcoinHash;
use bitcoin::{BlockHash, OutPoint};
use database::{
    DatabaseKey, DatabaseKeyPrefix, DatabaseValue, DecodingError, SerializableDatabaseValue,
};
use std::io::Cursor;

const DB_PREFIX_BLOCK_HASH: u8 = 0x30;
const DB_PREFIX_UTXO: u8 = 0x31;
const DB_PREFIX_LAST_BLOCK: u8 = 0x32;

#[derive(Clone, Debug)]
pub struct BlockHashKey(pub BlockHash);

#[derive(Clone, Debug)]
pub struct LastBlockKey;

#[derive(Clone, Debug)]
pub struct LastBlock(pub u32);

#[derive(Clone, Debug)]
pub struct UTXOKey(pub OutPoint);

impl DatabaseKeyPrefix for BlockHashKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(33);
        bytes.push(DB_PREFIX_BLOCK_HASH);
        bytes.extend_from_slice(&self.0[..]);
        bytes
    }
}

impl DatabaseKey for BlockHashKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        if data.len() != 33 {
            Err(DecodingError("BlockHashKey: expected 33 bytes".into()))
        } else if data[0] != DB_PREFIX_BLOCK_HASH {
            Err(DecodingError("BlockHashKey: wrong prefix".into()))
        } else {
            Ok(BlockHashKey(
                BlockHash::from_slice(&data[1..]).map_err(|e| DecodingError(e.into()))?,
            ))
        }
    }
}

impl DatabaseKeyPrefix for LastBlockKey {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_LAST_BLOCK]
    }
}

impl DatabaseKey for LastBlockKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        if data.len() != 1 {
            Err(DecodingError("LastBlockKey: expected 1 byte".into()))
        } else if data[0] != DB_PREFIX_LAST_BLOCK {
            Err(DecodingError("LastBlockKey: wrong prefix".into()))
        } else {
            Ok(LastBlockKey)
        }
    }
}

impl SerializableDatabaseValue for LastBlock {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }
}

impl DatabaseValue for LastBlock {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        if data.len() == 4 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(data);
            Ok(LastBlock(u32::from_be_bytes(bytes)))
        } else {
            Err(DecodingError("LastBlock: expected 4 bytes".into()))
        }
    }
}

impl DatabaseKeyPrefix for UTXOKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![DB_PREFIX_UTXO];
        self.0.consensus_encode(&mut bytes).unwrap();
        bytes
    }
}

impl DatabaseKey for UTXOKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        if data.len() < 1 {
            return Err(DecodingError("UTXOKey: expected at least 1 byte".into()));
        }

        if data[0] != DB_PREFIX_UTXO {
            return Err(DecodingError("UTXOKey: wrong prefix".into()));
        }

        Ok(UTXOKey(
            OutPoint::consensus_decode(Cursor::new(&data[1..]))
                .map_err(|e| DecodingError(e.into()))?,
        ))
    }
}
