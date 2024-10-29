use std::str::FromStr;

pub fn bitcoin29_to_bitcoin30_psbt(
    psbt: &bitcoin29::util::psbt::PartiallySignedTransaction,
) -> bitcoin30::psbt::PartiallySignedTransaction {
    bincode::deserialize(&bincode::serialize(psbt).expect("Failed to serialize bitcoin29 psbt"))
        .expect("Failed to convert bitcoin29 psbt to bitcoin30 psbt")
}

pub fn bitcoin30_to_bitcoin29_psbt(
    psbt: &bitcoin30::psbt::PartiallySignedTransaction,
) -> bitcoin29::util::psbt::PartiallySignedTransaction {
    bincode::deserialize(&bincode::serialize(psbt).expect("Failed to serialize bitcoin30 psbt"))
        .expect("Failed to convert bitcoin30 psbt to bitcoin29 psbt")
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

pub fn checked_address_to_unchecked_address(
    address: &bitcoin30::Address,
) -> bitcoin30::Address<bitcoin30::address::NetworkUnchecked> {
    bincode::deserialize(&bincode::serialize(address).expect("Failed to serialize bitcoin address"))
        .expect("Failed to convert checked bitcoin address to unchecked bitcoin address")
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

fn bitcoin32_to_bitcoin30_txid(txid: &bitcoin::Txid) -> bitcoin30::Txid {
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

pub fn bitcoin32_to_bitcoin30_schnorr_signature(
    signature: &bitcoin::secp256k1::schnorr::Signature,
) -> bitcoin30::secp256k1::schnorr::Signature {
    bitcoin30::secp256k1::schnorr::Signature::from_slice(signature.as_ref())
        .expect("Failed to convert bitcoin32 schnorr signature to bitcoin30 schnorr signature")
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
