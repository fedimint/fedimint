use std::str::FromStr;

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

pub fn bitcoin32_to_bitcoin30_address(address: &bitcoin::Address) -> bitcoin30::Address {
    // The bitcoin crate only allows for deserializing an address as unchecked.
    // However, we can safely call `assume_checked()` since the input address is
    // checked.
    bitcoin30::Address::from_str(&address.to_string())
        .expect("Failed to convert bitcoin32 address to bitcoin30 address")
        .assume_checked()
}

pub fn bitcoin32_to_bitcoin30_block_hash(
    hash: &bitcoin::block::BlockHash,
) -> bitcoin30::block::BlockHash {
    bitcoin30::block::BlockHash::from_raw_hash(bitcoin32_to_bitcoin30_sha256d_hash(
        &hash.to_raw_hash(),
    ))
}

pub fn bitcoin32_to_bitcoin30_unchecked_address(
    address: &bitcoin::Address<bitcoin::address::NetworkUnchecked>,
) -> bitcoin30::Address<bitcoin30::address::NetworkUnchecked> {
    // The bitcoin crate only implements `ToString` for checked addresses.
    // However, this is fine since we're returning an unchecked address.
    bitcoin30::Address::from_str(&address.assume_checked_ref().to_string())
        .expect("Failed to convert bitcoin32 address to bitcoin30 address")
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

fn bitcoin32_to_bitcoin30_sha256d_hash(
    hash: &bitcoin::hashes::sha256d::Hash,
) -> bitcoin30::hashes::sha256d::Hash {
    bitcoin30::hashes::sha256d::Hash::from_byte_array(*hash.as_ref())
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
