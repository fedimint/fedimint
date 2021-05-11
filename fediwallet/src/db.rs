use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash as BitcoinHash;
use bitcoin::{BlockHash, OutPoint, Transaction, Txid};
use database::{
    check_format, DatabaseKey, DatabaseKeyPrefix, DatabaseValue, DecodingError,
    SerializableDatabaseValue,
};
use std::io::Cursor;

const DB_PREFIX_BLOCK_HASH: u8 = 0x30;
const DB_PREFIX_UTXO: u8 = 0x31;
const DB_PREFIX_LAST_BLOCK: u8 = 0x32;
const DB_PREFIX_PEDNING_PEGOUT: u8 = 0x33;
const DB_PREFIX_UNSIGNED_TRANSACTION: u8 = 0x34;
const DB_PREFIX_PENDING_TRANSACTION: u8 = 0x35;

#[derive(Clone, Debug)]
pub struct BlockHashKey(pub BlockHash);

#[derive(Clone, Debug)]
pub struct LastBlockKey;

#[derive(Clone, Debug)]
pub struct LastBlock(pub u32);

#[derive(Clone, Debug)]
pub struct UTXOKey(pub OutPoint);

#[derive(Clone, Debug)]
pub struct UTXOPrefixKey;

#[derive(Clone, Debug)]
pub struct PendingPegOutKey(pub mint_api::TransactionId);

#[derive(Clone, Debug)]
pub struct PendingPegOutPrefixKey;

#[derive(Clone, Debug)]
pub struct UnsignedTransactionKey;

#[derive(Clone, Debug)]
pub struct PendingTransactionKey(pub Txid);

#[derive(Clone, Debug)]
pub struct PendingTransaction(pub Transaction);

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
        Ok(BlockHashKey(
            BlockHash::from_slice(check_format(data, DB_PREFIX_BLOCK_HASH, 32)?).unwrap(),
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
        check_format(data, DB_PREFIX_LAST_BLOCK, 0)?;
        Ok(LastBlockKey)
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
            Err(DecodingError::wrong_length(4, data.len()))
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
            return Err(DecodingError::wrong_length(1, data.len()));
        }

        if data[0] != DB_PREFIX_UTXO {
            return Err(DecodingError::wrong_prefix(DB_PREFIX_UTXO, data[0]));
        }

        Ok(UTXOKey(
            OutPoint::consensus_decode(Cursor::new(&data[1..]))
                .map_err(|e| DecodingError::other(e))?,
        ))
    }
}

impl DatabaseKeyPrefix for PendingPegOutKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(33);
        bytes.push(DB_PREFIX_PEDNING_PEGOUT);
        bytes.extend_from_slice(&self.0[..]);
        bytes
    }
}

impl DatabaseKey for PendingPegOutKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        Ok(PendingPegOutKey(
            mint_api::TransactionId::from_slice(check_format(data, DB_PREFIX_PEDNING_PEGOUT, 32)?)
                .unwrap(),
        ))
    }
}

impl DatabaseKeyPrefix for PendingPegOutPrefixKey {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_PEDNING_PEGOUT]
    }
}

impl DatabaseKeyPrefix for UnsignedTransactionKey {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_UNSIGNED_TRANSACTION]
    }
}

impl DatabaseKey for UnsignedTransactionKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        check_format(data, DB_PREFIX_UNSIGNED_TRANSACTION, 0)?;
        Ok(UnsignedTransactionKey)
    }
}

impl DatabaseKeyPrefix for UTXOPrefixKey {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_UTXO]
    }
}

impl DatabaseKeyPrefix for PendingTransactionKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(33);
        key.push(DB_PREFIX_PENDING_TRANSACTION);
        key.extend_from_slice(&self.0[..]);
        key
    }
}

impl DatabaseKey for PendingTransactionKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        Ok(PendingTransactionKey(
            Txid::from_slice(check_format(data, DB_PREFIX_PENDING_TRANSACTION, 32)?).unwrap(),
        ))
    }
}

impl SerializableDatabaseValue for PendingTransaction {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        self.0.consensus_encode(&mut data).expect("can't fail");
        data
    }
}

impl DatabaseValue for PendingTransaction {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        let tx = Transaction::consensus_decode(Cursor::new(data))
            .map_err(|e| DecodingError::other(e))?;
        Ok(PendingTransaction(tx))
    }
}
