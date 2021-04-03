use bitcoin::hashes::Hash as BitcoinHash;
use bitcoin::BlockHash;
use database::{
    DatabaseKey, DatabaseKeyPrefix, DatabaseValue, DecodingError, SerializableDatabaseValue,
};

const DB_PREFIX_BLOCK_HASHES: u8 = 0x30;
const DB_PREFIX_LAST_BLOCK: u8 = 0x32;

#[derive(Clone, Debug)]
pub struct BlockHashKey(pub BlockHash);

#[derive(Clone, Debug)]
pub struct LastBlockKey;

#[derive(Clone, Debug)]
pub struct LastBlock(pub u32);

impl DatabaseKeyPrefix for BlockHashKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.0[..].to_vec()
    }
}

impl DatabaseKey for BlockHashKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        Ok(BlockHashKey(
            BlockHash::from_slice(data).map_err(|e| DecodingError(e.into()))?,
        ))
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
