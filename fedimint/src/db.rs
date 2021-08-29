use database::{check_format, DatabaseKey, DatabaseKeyPrefix, DecodingError};
use mint_api::transaction::OutPoint;
use mint_api::{BitcoinHash, CoinNonce, TransactionId};
use std::convert::TryInto;

const DB_PREFIX_COIN_NONCE: u8 = 0x10;
const DB_PREFIX_PROPOSED_PARTIAL_SIG: u8 = 0x11;
const DB_PREFIX_RECEIVED_PARTIAL_SIG: u8 = 0x12;
const DB_PREFIX_OUTPUT_OUTCOME: u8 = 0x13;

#[derive(Debug)]
pub struct ReceivedPartialSignatureKey {
    pub request_id: OutPoint, // tx + output idx
    pub peer_id: u16,
}

#[derive(Debug)]
pub struct ReceivedPartialSignatureKeyOutputPrefix {
    pub request_id: OutPoint, // tx + output idx
}

#[derive(Debug)]
pub struct ReceivedPartialSignaturesKeyPrefix;

#[derive(Debug)]
pub struct ProposedPartialSignatureKey {
    pub request_id: OutPoint, // tx + output idx
}

#[derive(Debug)]
pub struct ProposedPartialSignaturesKeyPrefix;

/// Transaction id and output index identifying an output outcome
#[derive(Debug, Clone, Copy)]
pub struct OutputOutcomeKey(pub OutPoint);

#[derive(Debug)]
pub struct TransactionOutputOutcomeKeyPrefix {
    pub tx_hash: TransactionId,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct NonceKey(pub CoinNonce);

impl DatabaseKeyPrefix for ReceivedPartialSignatureKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(43);
        bytes.push(DB_PREFIX_RECEIVED_PARTIAL_SIG);
        bytes.extend_from_slice(&self.request_id.txid[..]);
        bytes.extend_from_slice(&self.request_id.out_idx.to_be_bytes()[..]);
        bytes.extend_from_slice(&self.peer_id.to_be_bytes()[..]);
        bytes.into()
    }
}

impl DatabaseKey for ReceivedPartialSignatureKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        let data = check_format(data, DB_PREFIX_RECEIVED_PARTIAL_SIG, 42)?;

        let tx_hash = TransactionId::from_slice(&data[0..32]).unwrap();

        let mut out_idx_bytes = [0u8; 8];
        out_idx_bytes.copy_from_slice(&data[32..40]);
        let out_idx = usize::from_be_bytes(out_idx_bytes);

        let mut peer_id_bytes = [0u8; 2];
        peer_id_bytes.copy_from_slice(&data[40..]);
        let peer_id = u16::from_be_bytes(peer_id_bytes);

        Ok(ReceivedPartialSignatureKey {
            request_id: OutPoint {
                txid: tx_hash,
                out_idx,
            },
            peer_id,
        })
    }
}

impl DatabaseKeyPrefix for ReceivedPartialSignatureKeyOutputPrefix {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(41);
        bytes.push(DB_PREFIX_RECEIVED_PARTIAL_SIG);
        bytes.extend_from_slice(&self.request_id.txid[..]);
        bytes.extend_from_slice(&self.request_id.out_idx.to_be_bytes()[..]);
        bytes
    }
}

impl DatabaseKeyPrefix for ReceivedPartialSignaturesKeyPrefix {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_RECEIVED_PARTIAL_SIG]
    }
}

impl DatabaseKeyPrefix for ProposedPartialSignatureKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(41);
        bytes.push(DB_PREFIX_PROPOSED_PARTIAL_SIG);
        bytes.extend_from_slice(&self.request_id.txid[..]);
        bytes.extend_from_slice(&self.request_id.out_idx.to_be_bytes()[..]);
        bytes.into()
    }
}

impl DatabaseKey for ProposedPartialSignatureKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        let data = check_format(data, DB_PREFIX_PROPOSED_PARTIAL_SIG, 40)?;

        let tx_hash = TransactionId::from_slice(&data[0..32]).unwrap();

        let mut out_idx_bytes = [0u8; 8];
        out_idx_bytes.copy_from_slice(&data[32..40]);
        let out_idx = usize::from_be_bytes(out_idx_bytes);

        Ok(ProposedPartialSignatureKey {
            request_id: OutPoint {
                txid: tx_hash,
                out_idx,
            },
        })
    }
}

impl DatabaseKeyPrefix for ProposedPartialSignaturesKeyPrefix {
    fn to_bytes(&self) -> Vec<u8> {
        vec![DB_PREFIX_PROPOSED_PARTIAL_SIG]
    }
}

impl DatabaseKeyPrefix for OutputOutcomeKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![DB_PREFIX_OUTPUT_OUTCOME];
        bytes.extend_from_slice(&self.0.txid[..]);
        bytes.extend_from_slice(&self.0.out_idx.to_le_bytes());
        bytes
    }
}

impl DatabaseKey for OutputOutcomeKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        let data = check_format(data, DB_PREFIX_OUTPUT_OUTCOME, 40)?;
        Ok(OutputOutcomeKey(OutPoint {
            txid: TransactionId::from_slice(&data[..32]).unwrap(),
            out_idx: usize::from_le_bytes(data[32..40].try_into().unwrap()),
        }))
    }
}

impl DatabaseKeyPrefix for TransactionOutputOutcomeKeyPrefix {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![DB_PREFIX_OUTPUT_OUTCOME];
        bytes.extend_from_slice(&self.tx_hash[..]);
        bytes
    }
}

impl DatabaseKeyPrefix for NonceKey {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![DB_PREFIX_COIN_NONCE];
        bytes.extend_from_slice(&self.0.to_bytes());
        bytes
    }
}

impl DatabaseKey for NonceKey {
    fn from_bytes(data: &[u8]) -> Result<Self, DecodingError> {
        if data.len() == 0 || data[0] != DB_PREFIX_COIN_NONCE {
            return Err(DecodingError::wrong_prefix(DB_PREFIX_COIN_NONCE, data[0]));
        }

        Ok(NonceKey(CoinNonce::from_bytes(data)))
    }
}
