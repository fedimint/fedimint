use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::hashes::Hash as BitcoinHash;
use bitcoin::{BlockHash, OutPoint, Transaction, Txid};
use database::{
    check_format, DatabaseKey, DatabaseKeyPrefix, DatabaseValue, DecodingError,
    SerializableDatabaseValue,
};
use std::convert::TryInto;
use std::io::{Cursor, Read};

const DB_PREFIX_BLOCK_HASH: u8 = 0x30;
const DB_PREFIX_UTXO: u8 = 0x31;
const DB_PREFIX_ROUND_CONSENSUS: u8 = 0x32;
const DB_PREFIX_PEDNING_PEGOUT: u8 = 0x33;
const DB_PREFIX_UNSIGNED_TRANSACTION: u8 = 0x34;
const DB_PREFIX_PENDING_TRANSACTION: u8 = 0x35;
const DB_PREFIX_PEG_OUT_TX_SIG_CI: u8 = 0x36;

#[derive(Clone, Debug)]
pub struct BlockHashKey(pub BlockHash);

#[derive(Clone, Debug)]
pub struct RoundConsensusKey;

#[derive(Clone, Debug)]
pub struct UTXOKey(pub OutPoint);

#[derive(Clone, Debug)]
pub struct UTXOPrefixKey;

#[derive(Clone, Debug)]
pub struct PendingPegOutKey(pub mint_api::transaction::OutPoint);

#[derive(Clone, Debug)]
pub struct PendingPegOutPrefixKey;

#[derive(Clone, Debug)]
pub struct UnsignedTransactionKey(pub Txid);

#[derive(Clone, Debug)]
pub struct PendingTransactionKey(pub Txid);

#[derive(Clone, Debug)]
pub struct PendingTransactionPrefixKey;

#[derive(Clone, Debug)]
pub struct PegOutTxSignatureCI(pub Txid);

#[derive(Clone, Debug)]
pub struct PegOutTxSignatureCIPrefix;

#[derive(Clone, Debug)]
pub struct PendingTransaction {
    pub tx: Transaction,
    pub tweak: Option<Vec<u8>>,
}

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

impl DatabaseKeyPrefix for RoundConsensusKey {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_ROUND_CONSENSUS]
    }
}

impl DatabaseKey for RoundConsensusKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        check_format(data, DB_PREFIX_ROUND_CONSENSUS, 0)?;
        Ok(RoundConsensusKey)
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
        bytes.extend_from_slice(&self.0.txid[..]);
        bytes.extend_from_slice(&self.0.out_idx.to_le_bytes());
        bytes
    }
}

impl DatabaseKey for PendingPegOutKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        let data = check_format(data, DB_PREFIX_PEDNING_PEGOUT, 40)?;

        let txid = mint_api::TransactionId::from_slice(&data[0..32]).unwrap();
        let out_idx = usize::from_le_bytes(data[32..].try_into().unwrap());
        Ok(PendingPegOutKey(mint_api::transaction::OutPoint {
            txid,
            out_idx,
        }))
    }
}

impl DatabaseKeyPrefix for PendingPegOutPrefixKey {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_PEDNING_PEGOUT]
    }
}

impl DatabaseKeyPrefix for UnsignedTransactionKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(33);
        key.push(DB_PREFIX_UNSIGNED_TRANSACTION);
        key.extend_from_slice(&self.0[..]);
        key
    }
}

impl DatabaseKey for UnsignedTransactionKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        Ok(UnsignedTransactionKey(
            Txid::from_slice(check_format(data, DB_PREFIX_UNSIGNED_TRANSACTION, 32)?).unwrap(),
        ))
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

impl DatabaseKeyPrefix for PendingTransactionPrefixKey {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_PENDING_TRANSACTION]
    }
}

impl DatabaseKey for PendingTransactionKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        Ok(PendingTransactionKey(
            Txid::from_slice(check_format(data, DB_PREFIX_PENDING_TRANSACTION, 32)?).unwrap(),
        ))
    }
}

impl DatabaseKeyPrefix for PegOutTxSignatureCI {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![DB_PREFIX_PEG_OUT_TX_SIG_CI];
        bytes.extend_from_slice(&self.0[..]);
        bytes
    }
}

impl DatabaseKey for PegOutTxSignatureCI {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        Ok(PegOutTxSignatureCI(
            Txid::from_slice(check_format(data, DB_PREFIX_PEG_OUT_TX_SIG_CI, 32)?)
                .expect("length checked before"),
        ))
    }
}

impl DatabaseKeyPrefix for PegOutTxSignatureCIPrefix {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_PEG_OUT_TX_SIG_CI]
    }
}

impl SerializableDatabaseValue for PendingTransaction {
    fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        self.tx.consensus_encode(&mut data).expect("can't fail");
        self.tweak
            .as_ref()
            .map(|tweak| data.extend_from_slice(tweak));
        data
    }
}

impl DatabaseValue for PendingTransaction {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        let mut cursor = Cursor::new(data);
        let tx = Transaction::consensus_decode(&mut cursor).map_err(|e| DecodingError::other(e))?;
        let mut tweak = Vec::new();
        cursor
            .read_to_end(&mut tweak)
            .expect("can't fail, may read 0 bytes");

        Ok(PendingTransaction {
            tx,
            tweak: if tweak.is_empty() { None } else { Some(tweak) },
        })
    }
}
