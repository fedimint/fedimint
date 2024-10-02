use std::str::FromStr;

use bitcoin30::hashes::Hash as Bitcoin30Hash;
use bitcoin_hashes::Hash;

pub fn bitcoin29_to_bitcoin30_psbt(
    psbt: &bitcoin29::util::psbt::PartiallySignedTransaction,
) -> bitcoin::psbt::Psbt {
    bincode::deserialize(&bincode::serialize(psbt).expect("Failed to serialize bitcoin29 psbt"))
        .expect("Failed to convert bitcoin29 psbt to bitcoin30 psbt")
}

pub fn bitcoin30_to_bitcoin29_psbt(
    psbt: &bitcoin::psbt::Psbt,
) -> bitcoin29::util::psbt::PartiallySignedTransaction {
    bincode::deserialize(&bincode::serialize(psbt).expect("Failed to serialize bitcoin30 psbt"))
        .expect("Failed to convert bitcoin30 psbt to bitcoin29 psbt")
}

pub fn bitcoin29_to_bitcoin30_network_magic(magic: u32) -> bitcoin::p2p::Magic {
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
    bitcoin::p2p::Magic::from_bytes(bytes)
}

pub fn bitcoin30_to_bitcoin29_network_magic(magic: &bitcoin::p2p::Magic) -> u32 {
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

pub fn bitcoin30_to_bitcoin32_outpoint(outpoint: &bitcoin30::OutPoint) -> bitcoin::OutPoint {
    bitcoin::OutPoint {
        txid: bitcoin30_to_bitcoin32_txid(&outpoint.txid),
        vout: outpoint.vout,
    }
}

fn bitcoin30_to_bitcoin32_txid(txid: &bitcoin30::Txid) -> bitcoin::Txid {
    bitcoin::Txid::from_slice(txid.as_ref())
        .expect("Failed to convert bitcoin30 txid to bitcoin32 txid")
}

pub fn bitcoin30_to_bitcoin32_secp256k1_pubkey(
    pubkey: &bitcoin30::secp256k1::PublicKey,
) -> bitcoin::secp256k1::PublicKey {
    bitcoin::secp256k1::PublicKey::from_str(&pubkey.to_string())
        .expect("Failed to convert bitcoin30 public key to bitcoin32 public key")
}

pub fn bitcoin32_to_bitcoin30_secp256k1_pubkey(
    pubkey: &bitcoin::secp256k1::PublicKey,
) -> bitcoin30::secp256k1::PublicKey {
    bitcoin30::secp256k1::PublicKey::from_str(&pubkey.to_string())
        .expect("Failed to convert bitcoin32 public key to bitcoin30 public key")
}

pub fn bitcoin32_to_bitcoin30_network(network: &bitcoin::Network) -> bitcoin30::Network {
    match network {
        bitcoin::Network::Bitcoin => bitcoin30::Network::Bitcoin,
        bitcoin::Network::Testnet => bitcoin30::Network::Testnet,
        bitcoin::Network::Signet => bitcoin30::Network::Signet,
        bitcoin::Network::Regtest => bitcoin30::Network::Regtest,
        _ => panic!("Unsupported network"),
    }
}

pub fn bitcoin32_to_bitcoin30_address(address: &bitcoin::Address) -> bitcoin30::Address {
    bitcoin30::Address::from_str(&address.to_string())
        .expect("Failed to convert bitcoin address to bitcoin30 address")
        .assume_checked()
}

pub fn bitcoin32_to_bitcoin30_bolt11_invoice(
    invoice: &lightning_invoice::Bolt11Invoice,
) -> lightning_invoice31::Bolt11Invoice {
    lightning_invoice31::Bolt11Invoice::from_str(&invoice.to_string())
        .expect("Failed to convert bitcoin32 bolt11 invoice to bitcoin30 bolt11 invoice")
}

pub fn bitcoin32_to_bitcoin30_payment_hash(
    hash: &bitcoin::hashes::sha256::Hash,
) -> bitcoin30::hashes::sha256::Hash {
    bitcoin30::hashes::sha256::Hash::from_slice(hash.as_ref())
        .expect("Failed to convert bitcoin32 payment hash to bitcoin30 payment hash")
}

pub fn bitcoin32_to_bitcoin30_payment_preimage(
    preimage: &lightning::ln::PaymentPreimage,
) -> lightning123::ln::PaymentPreimage {
    lightning123::ln::PaymentPreimage(preimage.0)
}

pub fn checked_address_to_unchecked_address(
    address: &bitcoin::Address,
) -> bitcoin::Address<bitcoin::address::NetworkUnchecked> {
    bincode::deserialize(&bincode::serialize(address).expect("Failed to serialize bitcoin address"))
        .expect("Failed to convert checked bitcoin address to unchecked bitcoin address")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_magic_conversions() {
        let bitcoin29_mainnet_magic: u32 = bitcoin29::network::constants::Network::Bitcoin.magic();
        let bitcoin30_mainnet_magic = bitcoin::Network::Bitcoin.magic();
        assert_eq!(
            bitcoin29_to_bitcoin30_network_magic(bitcoin29_mainnet_magic),
            bitcoin30_mainnet_magic
        );
        assert_eq!(
            bitcoin30_to_bitcoin29_network_magic(&bitcoin30_mainnet_magic),
            bitcoin29_mainnet_magic
        );

        let bitcoin29_testnet_magic: u32 = bitcoin29::network::constants::Network::Testnet.magic();
        let bitcoin30_testnet_magic = bitcoin::Network::Testnet.magic();
        assert_eq!(
            bitcoin29_to_bitcoin30_network_magic(bitcoin29_testnet_magic),
            bitcoin30_testnet_magic
        );
        assert_eq!(
            bitcoin30_to_bitcoin29_network_magic(&bitcoin30_testnet_magic),
            bitcoin29_testnet_magic
        );

        let bitcoin29_signet_magic: u32 = bitcoin29::network::constants::Network::Signet.magic();
        let bitcoin30_signet_magic = bitcoin::Network::Signet.magic();
        assert_eq!(
            bitcoin29_to_bitcoin30_network_magic(bitcoin29_signet_magic),
            bitcoin30_signet_magic
        );
        assert_eq!(
            bitcoin30_to_bitcoin29_network_magic(&bitcoin30_signet_magic),
            bitcoin29_signet_magic
        );

        let bitcoin29_regtest_magic: u32 = bitcoin29::network::constants::Network::Regtest.magic();
        let bitcoin30_regtest_magic = bitcoin::Network::Regtest.magic();
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
