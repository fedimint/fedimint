use std::str::FromStr;

use bitcoin::consensus::{Decodable, Encodable};
use bitcoin30::consensus::{Decodable as Bitcoin30Decodable, Encodable as Bitcoin30Encodable};
use bitcoin30::hashes::Hash;

pub fn bitcoin29_to_bitcoin32_psbt(
    psbt: &bitcoin29::util::psbt::PartiallySignedTransaction,
) -> bitcoin::psbt::Psbt {
    bincode::deserialize(&bincode::serialize(psbt).expect("Failed to serialize bitcoin29 psbt"))
        .expect("Failed to convert bitcoin29 psbt to bitcoin32 psbt")
}

pub fn bitcoin32_to_bitcoin29_psbt(
    psbt: &bitcoin::psbt::Psbt,
) -> bitcoin29::util::psbt::PartiallySignedTransaction {
    bincode::deserialize(&bincode::serialize(psbt).expect("Failed to serialize bitcoin32 psbt"))
        .expect("Failed to convert bitcoin32 psbt to bitcoin29 psbt")
}

pub fn bitcoin29_to_bitcoin32_network_magic(magic: u32) -> bitcoin::p2p::Magic {
    // Invert the byte order when converting from v0.32 to v0.29.
    // See the following bitcoin v0.29 and v0.32 code:
    // https://docs.rs/bitcoin/0.29.2/src/bitcoin/network/constants.rs.html#81-84
    // https://docs.rs/bitcoin/0.32.2/src/bitcoin/p2p/mod.rs.html#216-223
    let bytes = [
        (magic & 0xFF) as u8,
        ((magic >> 8) & 0xFF) as u8,
        ((magic >> 16) & 0xFF) as u8,
        ((magic >> 24) & 0xFF) as u8,
    ];
    bitcoin::p2p::Magic::from_bytes(bytes)
}

pub fn bitcoin32_to_bitcoin29_network_magic(magic: &bitcoin::p2p::Magic) -> u32 {
    let bytes = magic.to_bytes();
    // Invert the byte order when converting from v0.32 to v0.29.
    // See the following bitcoin v0.29 and v0.32 code:
    // https://docs.rs/bitcoin/0.29.2/src/bitcoin/network/constants.rs.html#81-84
    // https://docs.rs/bitcoin/0.32.2/src/bitcoin/p2p/mod.rs.html#216-223
    (u32::from(bytes[3]) << 24)
        | (u32::from(bytes[2]) << 16)
        | (u32::from(bytes[1]) << 8)
        | u32::from(bytes[0])
}

pub fn bitcoin30_checked_address_to_unchecked_address(
    address: &bitcoin30::Address,
) -> bitcoin30::Address<bitcoin30::address::NetworkUnchecked> {
    bincode::deserialize(&bincode::serialize(address).expect("Failed to serialize bitcoin address"))
        .expect("Failed to convert checked bitcoin address to unchecked bitcoin address")
}

pub fn bitcoin32_checked_address_to_unchecked_address(
    address: &bitcoin::Address,
) -> bitcoin::Address<bitcoin::address::NetworkUnchecked> {
    address.as_unchecked().clone()
}

pub fn bitcoin30_to_bitcoin32_invoice(
    invoice: &lightning_invoice::Bolt11Invoice,
) -> lightning_invoice32::Bolt11Invoice {
    lightning_invoice32::Bolt11Invoice::from_str(&invoice.to_string())
        .expect("Failed to convert bitcoin30 invoice to bitcoin32 invoice")
}

pub fn bitcoin30_to_bitcoin32_keypair(
    keypair: &bitcoin30::secp256k1::KeyPair,
) -> bitcoin::secp256k1::Keypair {
    bitcoin::secp256k1::Keypair::from_secret_key(
        bitcoin::secp256k1::SECP256K1,
        &bitcoin30_to_bitcoin32_secp256k1_secret_key(&keypair.secret_key()),
    )
}

pub fn bitcoin32_to_bitcoin30_keypair(
    keypair: &bitcoin::secp256k1::Keypair,
) -> bitcoin30::secp256k1::KeyPair {
    bitcoin30::secp256k1::KeyPair::from_secret_key(
        bitcoin30::secp256k1::SECP256K1,
        &bitcoin32_to_bitcoin30_secp256k1_secret_key(&keypair.secret_key()),
    )
}

pub fn bitcoin30_to_bitcoin32_secp256k1_secret_key(
    secret_key: &bitcoin30::secp256k1::SecretKey,
) -> bitcoin::secp256k1::SecretKey {
    bitcoin::secp256k1::SecretKey::from_slice(secret_key.as_ref()).expect(
        "Failed to convert bitcoin30 secp256k1 secret key to bitcoin32 secp256k1 secret key",
    )
}

pub fn bitcoin32_to_bitcoin30_secp256k1_secret_key(
    secret_key: &bitcoin::secp256k1::SecretKey,
) -> bitcoin30::secp256k1::SecretKey {
    bitcoin30::secp256k1::SecretKey::from_slice(secret_key.as_ref()).expect(
        "Failed to convert bitcoin32 secp256k1 secret key to bitcoin30 secp256k1 secret key",
    )
}

pub fn bitcoin30_to_bitcoin32_secp256k1_pubkey(
    pubkey: &bitcoin30::secp256k1::PublicKey,
) -> bitcoin::secp256k1::PublicKey {
    bitcoin::secp256k1::PublicKey::from_slice(&pubkey.serialize())
        .expect("Failed to convert bitcoin30 secp256k1 pubkey to bitcoin32 secp256k1 pubkey")
}

pub fn bitcoin32_to_bitcoin30_secp256k1_pubkey(
    pubkey: &bitcoin::secp256k1::PublicKey,
) -> bitcoin30::secp256k1::PublicKey {
    bitcoin30::secp256k1::PublicKey::from_slice(&pubkey.serialize())
        .expect("Failed to convert bitcoin32 secp256k1 pubkey to bitcoin30 secp256k1 pubkey")
}

pub fn bitcoin30_to_bitcoin32_address(address: &bitcoin30::Address) -> bitcoin::Address {
    // The bitcoin crate only allows for deserializing an address as unchecked.
    // However, we can safely call `assume_checked()` since the input address is
    // checked.
    bitcoin::Address::from_str(&address.to_string())
        .expect("Failed to convert bitcoin30 address to bitcoin32 address")
        .assume_checked()
}

pub fn bitcoin32_to_bitcoin30_address(address: &bitcoin::Address) -> bitcoin30::Address {
    // The bitcoin crate only allows for deserializing an address as unchecked.
    // However, we can safely call `assume_checked()` since the input address is
    // checked.
    bitcoin30::Address::from_str(&address.to_string())
        .expect("Failed to convert bitcoin32 address to bitcoin30 address")
        .assume_checked()
}

pub fn bitcoin30_to_bitcoin32_block_header(
    block_header: &bitcoin30::block::Header,
) -> bitcoin::block::Header {
    bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(block_header.version.to_consensus()),
        prev_blockhash: bitcoin::block::BlockHash::from_raw_hash(
            bitcoin30_to_bitcoin32_sha256d_hash(&block_header.prev_blockhash.to_raw_hash()),
        ),
        merkle_root: bitcoin::hash_types::TxMerkleNode::from_raw_hash(
            bitcoin30_to_bitcoin32_sha256d_hash(&block_header.merkle_root.to_raw_hash()),
        ),
        time: block_header.time,
        bits: bitcoin::pow::CompactTarget::from_consensus(block_header.bits.to_consensus()),
        nonce: block_header.nonce,
    }
}

pub fn bitcoin32_to_bitcoin30_block_header(
    block_header: &bitcoin::block::Header,
) -> bitcoin30::block::Header {
    bitcoin30::block::Header {
        version: bitcoin30::block::Version::from_consensus(block_header.version.to_consensus()),
        prev_blockhash: bitcoin30::block::BlockHash::from_raw_hash(
            bitcoin32_to_bitcoin30_sha256d_hash(&block_header.prev_blockhash.to_raw_hash()),
        ),
        merkle_root: bitcoin30::hash_types::TxMerkleNode::from_raw_hash(
            bitcoin32_to_bitcoin30_sha256d_hash(&block_header.merkle_root.to_raw_hash()),
        ),
        time: block_header.time,
        bits: bitcoin30::pow::CompactTarget::from_consensus(block_header.bits.to_consensus()),
        nonce: block_header.nonce,
    }
}

pub fn bitcoin32_to_bitcoin30_partial_merkle_tree(
    partial_merkle_tree: &bitcoin::merkle_tree::PartialMerkleTree,
) -> bitcoin30::merkle_tree::PartialMerkleTree {
    let mut bytes = vec![];
    partial_merkle_tree
        .consensus_encode(&mut bytes)
        .expect("Failed to consensus-encode bitcoin32 partial merkle tree");
    let mut cursor = std::io::Cursor::new(bytes);
    bitcoin30::merkle_tree::PartialMerkleTree::consensus_decode(&mut cursor)
        .expect("Failed to convert bitcoin32 partial merkle tree to bitcoin30 partial merkle tree")
}

fn bitcoin30_to_bitcoin32_witness(witness: &bitcoin30::Witness) -> bitcoin::Witness {
    let mut bytes = vec![];
    witness
        .consensus_encode(&mut bytes)
        .expect("Failed to consensus-encode bitcoin30 witness");
    let mut cursor = bitcoin::io::Cursor::new(bytes);
    bitcoin::Witness::consensus_decode(&mut cursor)
        .expect("Failed to convert bitcoin30 witness to bitcoin32 witness")
}

fn bitcoin32_to_bitcoin30_witness(witness: &bitcoin::Witness) -> bitcoin30::Witness {
    let mut bytes = vec![];
    witness
        .consensus_encode(&mut bytes)
        .expect("Failed to consensus-encode bitcoin32 witness");
    let mut cursor = std::io::Cursor::new(bytes);
    bitcoin30::Witness::consensus_decode(&mut cursor)
        .expect("Failed to convert bitcoin32 witness to bitcoin30 witness")
}

fn bitcoin30_to_bitcoin32_txin(txin: &bitcoin30::TxIn) -> bitcoin::TxIn {
    bitcoin::TxIn {
        previous_output: bitcoin30_to_bitcoin32_outpoint(&txin.previous_output),
        script_sig: bitcoin30_to_bitcoin32_script_buf(&txin.script_sig),
        sequence: bitcoin::Sequence(txin.sequence.0),
        witness: bitcoin30_to_bitcoin32_witness(&txin.witness),
    }
}

fn bitcoin32_to_bitcoin30_txin(txin: &bitcoin::TxIn) -> bitcoin30::TxIn {
    bitcoin30::TxIn {
        previous_output: bitcoin32_to_bitcoin30_outpoint(&txin.previous_output),
        script_sig: bitcoin32_to_bitcoin30_script_buf(&txin.script_sig),
        sequence: bitcoin30::Sequence(txin.sequence.0),
        witness: bitcoin32_to_bitcoin30_witness(&txin.witness),
    }
}

fn bitcoin30_to_bitcoin32_txout(txout: &bitcoin30::TxOut) -> bitcoin::TxOut {
    bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(txout.value),
        script_pubkey: bitcoin30_to_bitcoin32_script_buf(&txout.script_pubkey),
    }
}

fn bitcoin32_to_bitcoin30_txout(txout: &bitcoin::TxOut) -> bitcoin30::TxOut {
    bitcoin30::TxOut {
        value: bitcoin32_to_bitcoin30_amount(&txout.value).to_sat(),
        script_pubkey: bitcoin32_to_bitcoin30_script_buf(&txout.script_pubkey),
    }
}

fn bitcoin30_to_bitcoin32_locktime(
    locktime: bitcoin30::blockdata::locktime::absolute::LockTime,
) -> bitcoin::blockdata::locktime::absolute::LockTime {
    match locktime {
        bitcoin30::blockdata::locktime::absolute::LockTime::Blocks(height) => {
            bitcoin::blockdata::locktime::absolute::LockTime::Blocks(
                bitcoin::blockdata::locktime::absolute::Height::from_consensus(
                    height.to_consensus_u32(),
                )
                .expect("Failed to convert bitcoin30 block height locktime to bitcoin32 block height locktime"),
            )
        }
        bitcoin30::blockdata::locktime::absolute::LockTime::Seconds(time) => {
            bitcoin::blockdata::locktime::absolute::LockTime::Seconds(
                bitcoin::blockdata::locktime::absolute::Time::from_consensus(time.to_consensus_u32()).expect("Failed to convert bitcoin30 timestamp locktime to bitcoin32 timestamp locktime"),
            )
        }
    }
}

fn bitcoin32_to_bitcoin30_locktime(
    locktime: bitcoin::blockdata::locktime::absolute::LockTime,
) -> bitcoin30::blockdata::locktime::absolute::LockTime {
    match locktime {
        bitcoin::blockdata::locktime::absolute::LockTime::Blocks(height) => {
            bitcoin30::blockdata::locktime::absolute::LockTime::Blocks(
                bitcoin30::blockdata::locktime::absolute::Height::from_consensus(
                    height.to_consensus_u32(),
                )
                .expect("Failed to convert bitcoin32 block height locktime to bitcoin30 block height locktime"),
            )
        }
        bitcoin::blockdata::locktime::absolute::LockTime::Seconds(time) => {
            bitcoin30::blockdata::locktime::absolute::LockTime::Seconds(
                bitcoin30::blockdata::locktime::absolute::Time::from_consensus(time.to_consensus_u32()).expect("Failed to convert bitcoin32 timestamp locktime to bitcoin30 timestamp locktime"),
            )
        }
    }
}

pub fn bitcoin32_to_bitcoin30_tx(tx: &bitcoin::Transaction) -> bitcoin30::Transaction {
    bitcoin30::Transaction {
        version: tx.version.0,
        lock_time: bitcoin32_to_bitcoin30_locktime(tx.lock_time),
        input: tx.input.iter().map(bitcoin32_to_bitcoin30_txin).collect(),
        output: tx.output.iter().map(bitcoin32_to_bitcoin30_txout).collect(),
    }
}

pub fn bitcoin30_to_bitcoin32_tx(tx: &bitcoin30::Transaction) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: bitcoin::blockdata::transaction::Version(tx.version),
        lock_time: bitcoin30_to_bitcoin32_locktime(tx.lock_time),
        input: tx.input.iter().map(bitcoin30_to_bitcoin32_txin).collect(),
        output: tx.output.iter().map(bitcoin30_to_bitcoin32_txout).collect(),
    }
}

pub fn bitcoin_32_to_bitcoin30_txout(txout: &bitcoin::TxOut) -> bitcoin30::TxOut {
    bitcoin30::TxOut {
        value: bitcoin32_to_bitcoin30_amount(&txout.value).to_sat(),
        script_pubkey: bitcoin32_to_bitcoin30_script_buf(&txout.script_pubkey),
    }
}

pub fn bitcoin30_to_bitcoin32_script_buf(script: &bitcoin30::ScriptBuf) -> bitcoin::ScriptBuf {
    bitcoin::ScriptBuf::from(script.as_bytes().to_vec())
}

pub fn bitcoin32_to_bitcoin30_script_buf(script: &bitcoin::ScriptBuf) -> bitcoin30::ScriptBuf {
    bitcoin30::ScriptBuf::from(script.as_bytes().to_vec())
}

pub fn bitcoin30_to_bitcoin32_block_hash(
    hash: &bitcoin30::block::BlockHash,
) -> bitcoin::block::BlockHash {
    bitcoin::block::BlockHash::from_raw_hash(bitcoin30_to_bitcoin32_sha256d_hash(
        &hash.to_raw_hash(),
    ))
}

pub fn bitcoin32_to_bitcoin30_block_hash(
    hash: &bitcoin::block::BlockHash,
) -> bitcoin30::block::BlockHash {
    bitcoin30::block::BlockHash::from_raw_hash(bitcoin32_to_bitcoin30_sha256d_hash(
        &hash.to_raw_hash(),
    ))
}

pub fn bitcoin30_to_bitcoin32_unchecked_address(
    address: &bitcoin30::Address<bitcoin30::address::NetworkUnchecked>,
) -> bitcoin::Address<bitcoin::address::NetworkUnchecked> {
    // The bitcoin crate only implements `ToString` for checked addresses.
    // However, this is fine since we're returning an unchecked address.
    bitcoin::Address::from_str(&address.clone().assume_checked().to_string())
        .expect("Failed to convert bitcoin30 address to bitcoin32 address")
}

pub fn bitcoin32_to_bitcoin30_unchecked_address(
    address: &bitcoin::Address<bitcoin::address::NetworkUnchecked>,
) -> bitcoin30::Address<bitcoin30::address::NetworkUnchecked> {
    // The bitcoin crate only implements `ToString` for checked addresses.
    // However, this is fine since we're returning an unchecked address.
    bitcoin30::Address::from_str(&address.assume_checked_ref().to_string())
        .expect("Failed to convert bitcoin32 address to bitcoin30 address")
}

pub fn bitcoin30_to_bitcoin32_amount(amount: &bitcoin30::Amount) -> bitcoin::Amount {
    bitcoin::Amount::from_sat(amount.to_sat())
}

pub fn bitcoin32_to_bitcoin30_amount(amount: &bitcoin::Amount) -> bitcoin30::Amount {
    bitcoin30::Amount::from_sat(amount.to_sat())
}

pub fn bitcoin30_to_bitcoin32_network(network: &bitcoin30::Network) -> bitcoin::Network {
    match *network {
        bitcoin30::Network::Bitcoin => bitcoin::Network::Bitcoin,
        bitcoin30::Network::Testnet => bitcoin::Network::Testnet,
        bitcoin30::Network::Signet => bitcoin::Network::Signet,
        bitcoin30::Network::Regtest => bitcoin::Network::Regtest,
        _ => panic!("There are no other enum cases, this should never be hit."),
    }
}

pub fn bitcoin32_to_bitcoin30_network(network: &bitcoin::Network) -> bitcoin30::Network {
    match *network {
        bitcoin::Network::Bitcoin => bitcoin30::Network::Bitcoin,
        bitcoin::Network::Testnet => bitcoin30::Network::Testnet,
        bitcoin::Network::Signet => bitcoin30::Network::Signet,
        bitcoin::Network::Regtest => bitcoin30::Network::Regtest,
        _ => panic!("There are no other enum cases, this should never be hit."),
    }
}

pub fn bitcoin30_to_bitcoin32_txid(txid: &bitcoin30::Txid) -> bitcoin::Txid {
    bitcoin::Txid::from_str(&txid.to_string())
        .expect("Failed to convert bitcoin30 txid to bitcoin32 txid")
}

pub fn bitcoin32_to_bitcoin30_txid(txid: &bitcoin::Txid) -> bitcoin30::Txid {
    bitcoin30::Txid::from_str(&txid.to_string())
        .expect("Failed to convert bitcoin32 txid to bitcoin30 txid")
}

pub fn bitcoin30_to_bitcoin32_outpoint(outpoint: &bitcoin30::OutPoint) -> bitcoin::OutPoint {
    bitcoin::OutPoint {
        txid: bitcoin30_to_bitcoin32_txid(&outpoint.txid),
        vout: outpoint.vout,
    }
}

pub fn bitcoin32_to_bitcoin30_outpoint(outpoint: &bitcoin::OutPoint) -> bitcoin30::OutPoint {
    bitcoin30::OutPoint {
        txid: bitcoin32_to_bitcoin30_txid(&outpoint.txid),
        vout: outpoint.vout,
    }
}

pub fn bitcoin30_to_bitcoin32_payment_preimage(
    preimage: &lightning::ln::PaymentPreimage,
) -> lightning_types::payment::PaymentPreimage {
    lightning_types::payment::PaymentPreimage(preimage.0)
}

pub fn bitcoin30_to_bitcoin32_sha256_hash(
    hash: &bitcoin30::hashes::sha256::Hash,
) -> bitcoin::hashes::sha256::Hash {
    *bitcoin::hashes::sha256::Hash::from_bytes_ref(hash.as_ref())
}

pub fn bitcoin32_to_bitcoin30_sha256_hash(
    hash: &bitcoin::hashes::sha256::Hash,
) -> bitcoin30::hashes::sha256::Hash {
    bitcoin30::hashes::sha256::Hash::from_slice(hash.as_ref()).expect("Invalid hash length")
}

fn bitcoin30_to_bitcoin32_sha256d_hash(
    hash: &bitcoin30::hashes::sha256d::Hash,
) -> bitcoin::hashes::sha256d::Hash {
    *bitcoin::hashes::sha256d::Hash::from_bytes_ref(hash.as_ref())
}

fn bitcoin32_to_bitcoin30_sha256d_hash(
    hash: &bitcoin::hashes::sha256d::Hash,
) -> bitcoin30::hashes::sha256d::Hash {
    bitcoin30::hashes::sha256d::Hash::from_byte_array(*hash.as_ref())
}

pub fn bitcoin30_to_bitcoin32_schnorr_signature(
    signature: &bitcoin30::secp256k1::schnorr::Signature,
) -> bitcoin::secp256k1::schnorr::Signature {
    bitcoin::secp256k1::schnorr::Signature::from_slice(signature.as_ref())
        .expect("Failed to convert bitcoin30 schnorr signature to bitcoin32 schnorr signature")
}

pub fn bitcoin32_to_bitcoin30_schnorr_signature(
    signature: &bitcoin::secp256k1::schnorr::Signature,
) -> bitcoin30::secp256k1::schnorr::Signature {
    bitcoin30::secp256k1::schnorr::Signature::from_slice(signature.as_ref())
        .expect("Failed to convert bitcoin32 schnorr signature to bitcoin30 schnorr signature")
}

pub fn bitcoin32_to_bitcoin30_recoverable_signature(
    signature: &bitcoin::secp256k1::ecdsa::RecoverableSignature,
) -> bitcoin30::secp256k1::ecdsa::RecoverableSignature {
    let (recovery_id, data) = signature.serialize_compact();

    bitcoin30::secp256k1::ecdsa::RecoverableSignature::from_compact(
        &data,
        bitcoin30::secp256k1::ecdsa::RecoveryId::from_i32(recovery_id.to_i32())
            .expect("Invalid recovery id"),
    )
    .expect("Failed to convert bitcoin32 recoverable signature to bitcoin30 recoverable signature")
}

pub fn bitcoin30_to_bitcoin32_secp256k1_message(
    message: &bitcoin30::secp256k1::Message,
) -> bitcoin::secp256k1::Message {
    bitcoin::secp256k1::Message::from_digest_slice(message.as_ref())
        .expect("Failed to convert bitcoin30 message to bitcoin32 message")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_magic_conversions() {
        let bitcoin29_mainnet_magic: u32 = bitcoin29::network::constants::Network::Bitcoin.magic();
        let bitcoin32_mainnet_magic = bitcoin::network::Network::Bitcoin.magic();
        assert_eq!(
            bitcoin29_to_bitcoin32_network_magic(bitcoin29_mainnet_magic),
            bitcoin32_mainnet_magic
        );
        assert_eq!(
            bitcoin32_to_bitcoin29_network_magic(&bitcoin32_mainnet_magic),
            bitcoin29_mainnet_magic
        );

        let bitcoin29_testnet_magic: u32 = bitcoin29::network::constants::Network::Testnet.magic();
        let bitcoin32_testnet_magic = bitcoin::network::Network::Testnet.magic();
        assert_eq!(
            bitcoin29_to_bitcoin32_network_magic(bitcoin29_testnet_magic),
            bitcoin32_testnet_magic
        );
        assert_eq!(
            bitcoin32_to_bitcoin29_network_magic(&bitcoin32_testnet_magic),
            bitcoin29_testnet_magic
        );

        let bitcoin29_signet_magic: u32 = bitcoin29::network::constants::Network::Signet.magic();
        let bitcoin32_signet_magic = bitcoin::network::Network::Signet.magic();
        assert_eq!(
            bitcoin29_to_bitcoin32_network_magic(bitcoin29_signet_magic),
            bitcoin32_signet_magic
        );
        assert_eq!(
            bitcoin32_to_bitcoin29_network_magic(&bitcoin32_signet_magic),
            bitcoin29_signet_magic
        );

        let bitcoin29_regtest_magic: u32 = bitcoin29::network::constants::Network::Regtest.magic();
        let bitcoin32_regtest_magic = bitcoin::network::Network::Regtest.magic();
        assert_eq!(
            bitcoin29_to_bitcoin32_network_magic(bitcoin29_regtest_magic),
            bitcoin32_regtest_magic
        );
        assert_eq!(
            bitcoin32_to_bitcoin29_network_magic(&bitcoin32_regtest_magic),
            bitcoin29_regtest_magic
        );
    }
}
