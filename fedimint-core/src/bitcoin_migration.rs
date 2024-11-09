use std::str::FromStr;

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

pub fn bitcoin32_to_bitcoin30_address(address: &bitcoin::Address) -> bitcoin30::Address {
    // The bitcoin crate only allows for deserializing an address as unchecked.
    // However, we can safely call `assume_checked()` since the input address is
    // checked.
    bitcoin30::Address::from_str(&address.to_string())
        .expect("Failed to convert bitcoin32 address to bitcoin30 address")
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

pub fn bitcoin30_to_bitcoin32_network(network: &bitcoin30::Network) -> bitcoin::Network {
    match *network {
        bitcoin30::Network::Bitcoin => bitcoin::Network::Bitcoin,
        bitcoin30::Network::Testnet => bitcoin::Network::Testnet,
        bitcoin30::Network::Signet => bitcoin::Network::Signet,
        bitcoin30::Network::Regtest => bitcoin::Network::Regtest,
        _ => panic!("There are no other enum cases, this should never be hit."),
    }
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
