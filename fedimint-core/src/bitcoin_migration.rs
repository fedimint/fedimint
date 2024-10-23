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

pub fn bitcoin29_to_bitcoin30_network_magic(magic: u32) -> bitcoin30::network::Magic {
    // Invert the byte order when converting from v0.29 to v0.30.
    // See the following bitcoin v0.29 and v0.30 code:
    // https://docs.rs/bitcoin/0.29.2/src/bitcoin/network/constants.rs.html#81-84
    // https://docs.rs/bitcoin/0.30.2/src/bitcoin/network/constants.rs.html#251-258
    let bytes = [
        (magic & 0xFF) as u8,
        ((magic >> 8) & 0xFF) as u8,
        ((magic >> 16) & 0xFF) as u8,
        ((magic >> 24) & 0xFF) as u8,
    ];
    bitcoin30::network::Magic::from_bytes(bytes)
}

pub fn bitcoin30_to_bitcoin29_network_magic(magic: &bitcoin30::network::Magic) -> u32 {
    let bytes = magic.to_bytes();
    // Invert the byte order when converting from v0.30 to v0.29.
    // See the following bitcoin v0.29 and v0.30 code:
    // https://docs.rs/bitcoin/0.29.2/src/bitcoin/network/constants.rs.html#81-84
    // https://docs.rs/bitcoin/0.30.2/src/bitcoin/network/constants.rs.html#251-258
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
    bincode::deserialize(
        &bincode::serialize(&invoice).expect("Failed to serialize bitcoin30 invoice"),
    )
    .expect("Failed to convert bitcoin30 invoice to bitcoin32 invoice")
}

pub fn bitcoin30_to_bitcoin32_keypair(
    keypair: &bitcoin30::secp256k1::KeyPair,
) -> bitcoin::secp256k1::Keypair {
    bincode::deserialize(
        &bincode::serialize(&keypair).expect("Failed to serialize bitcoin30 keypair"),
    )
    .expect("Failed to convert bitcoin30 keypair to bitcoin32 keypair")
}

pub fn bitcoin32_to_bitcoin30_keypair(
    keypair: &bitcoin::secp256k1::Keypair,
) -> bitcoin30::secp256k1::KeyPair {
    bincode::deserialize(
        &bincode::serialize(&keypair).expect("Failed to serialize bitcoin32 keypair"),
    )
    .expect("Failed to convert bitcoin32 keypair to bitcoin30 keypair")
}

pub fn bitcoin30_to_bitcoin32_secp256k1_secret_key(
    secret_key: &bitcoin30::secp256k1::SecretKey,
) -> bitcoin::secp256k1::SecretKey {
    bincode::deserialize(
        &bincode::serialize(&secret_key)
            .expect("Failed to serialize bitcoin30 secp256k1 secret key"),
    )
    .expect("Failed to convert bitcoin30 secp256k1 secret key to bitcoin32 secp256k1 secret key")
}

pub fn bitcoin32_to_bitcoin30_secp256k1_secret_key(
    secret_key: &bitcoin::secp256k1::SecretKey,
) -> bitcoin30::secp256k1::SecretKey {
    bincode::deserialize(
        &bincode::serialize(&secret_key)
            .expect("Failed to serialize bitcoin32 secp256k1 secret key"),
    )
    .expect("Failed to convert bitcoin32 secp256k1 secret key to bitcoin30 secp256k1 secret key")
}

pub fn bitcoin30_to_bitcoin32_secp256k1_pubkey(
    pubkey: &bitcoin30::secp256k1::PublicKey,
) -> bitcoin::secp256k1::PublicKey {
    bincode::deserialize(
        &bincode::serialize(&pubkey).expect("Failed to serialize bitcoin30 secp256k1 pubkey"),
    )
    .expect("Failed to convert bitcoin30 secp256k1 pubkey to bitcoin32 secp256k1 pubkey")
}

pub fn bitcoin32_to_bitcoin30_secp256k1_pubkey(
    pubkey: &bitcoin::secp256k1::PublicKey,
) -> bitcoin30::secp256k1::PublicKey {
    bincode::deserialize(
        &bincode::serialize(&pubkey).expect("Failed to serialize bitcoin32 secp256k1 pubkey"),
    )
    .expect("Failed to convert bitcoin32 secp256k1 pubkey to bitcoin30 secp256k1 pubkey")
}

pub fn bitcoin30_to_bitcoin32_address(address: &bitcoin30::Address) -> bitcoin::Address {
    // The bitcoin crate only allows for deserializing an address as unchecked.
    // However, we can safely call `assume_checked()` since the input address is
    // checked.
    bincode::deserialize::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>(
        &bincode::serialize(address).expect("Failed to serialize bitcoin30 address"),
    )
    .expect("Failed to convert bitcoin30 address to bitcoin32 address")
    .assume_checked()
}

pub fn bitcoin32_to_bitcoin30_unchecked_address(
    address: &bitcoin::Address<bitcoin::address::NetworkUnchecked>,
) -> bitcoin30::Address<bitcoin30::address::NetworkUnchecked> {
    // The bitcoin crate only allows for deserializing an address as unchecked.
    // However, we can safely call `assume_checked()` since the input address is
    // checked.
    bincode::deserialize(
        &bincode::serialize(address).expect("Failed to serialize bitcoin32 address"),
    )
    .expect("Failed to convert bitcoin32 address to bitcoin30 address")
}

pub fn bitcoin30_to_bitcoin32_amount(amount: &bitcoin30::Amount) -> bitcoin::Amount {
    bitcoin::Amount::from_sat(amount.to_sat())
}

pub fn bitcoin32_to_bitcoin30_amount(amount: &bitcoin::Amount) -> bitcoin30::Amount {
    bitcoin30::Amount::from_sat(amount.to_sat())
}

pub fn bitcoin30_to_bitcoin32_network(network: &bitcoin30::Network) -> bitcoin::Network {
    bincode::deserialize(
        &bincode::serialize(network).expect("Failed to serialize bitcoin30 network"),
    )
    .expect("Failed to convert bitcoin30 network to bitcoin32 network")
}

fn bitcoin30_to_bitcoin32_txid(txid: &bitcoin30::Txid) -> bitcoin::Txid {
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
    bincode::deserialize(
        &bincode::serialize(&hash).expect("Failed to serialize bitcoin30 sha256 hash"),
    )
    .expect("Failed to convert bitcoin30 sha256 hash to bitcoin32 sha256 hash")
}

pub fn bitcoin32_to_bitcoin30_schnorr_signature(
    signature: &bitcoin::secp256k1::schnorr::Signature,
) -> bitcoin30::secp256k1::schnorr::Signature {
    bincode::deserialize(
        &bincode::serialize(&signature).expect("Failed to serialize bitcoin32 schnorr signature"),
    )
    .expect("Failed to convert bitcoin32 schnorr signature to bitcoin30 schnorr signature")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_magic_conversions() {
        let bitcoin29_mainnet_magic: u32 = bitcoin29::network::constants::Network::Bitcoin.magic();
        let bitcoin30_mainnet_magic = bitcoin30::network::constants::Network::Bitcoin.magic();
        assert_eq!(
            bitcoin29_to_bitcoin30_network_magic(bitcoin29_mainnet_magic),
            bitcoin30_mainnet_magic
        );
        assert_eq!(
            bitcoin30_to_bitcoin29_network_magic(&bitcoin30_mainnet_magic),
            bitcoin29_mainnet_magic
        );

        let bitcoin29_testnet_magic: u32 = bitcoin29::network::constants::Network::Testnet.magic();
        let bitcoin30_testnet_magic = bitcoin30::network::constants::Network::Testnet.magic();
        assert_eq!(
            bitcoin29_to_bitcoin30_network_magic(bitcoin29_testnet_magic),
            bitcoin30_testnet_magic
        );
        assert_eq!(
            bitcoin30_to_bitcoin29_network_magic(&bitcoin30_testnet_magic),
            bitcoin29_testnet_magic
        );

        let bitcoin29_signet_magic: u32 = bitcoin29::network::constants::Network::Signet.magic();
        let bitcoin30_signet_magic = bitcoin30::network::constants::Network::Signet.magic();
        assert_eq!(
            bitcoin29_to_bitcoin30_network_magic(bitcoin29_signet_magic),
            bitcoin30_signet_magic
        );
        assert_eq!(
            bitcoin30_to_bitcoin29_network_magic(&bitcoin30_signet_magic),
            bitcoin29_signet_magic
        );

        let bitcoin29_regtest_magic: u32 = bitcoin29::network::constants::Network::Regtest.magic();
        let bitcoin30_regtest_magic = bitcoin30::network::constants::Network::Regtest.magic();
        assert_eq!(
            bitcoin29_to_bitcoin30_network_magic(bitcoin29_regtest_magic),
            bitcoin30_regtest_magic
        );
        assert_eq!(
            bitcoin30_to_bitcoin29_network_magic(&bitcoin30_regtest_magic),
            bitcoin29_regtest_magic
        );
    }
}
