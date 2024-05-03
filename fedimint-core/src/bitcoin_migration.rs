pub fn bitcoin29_to_bitcoin30_psbt(
    psbt: &bitcoin29::util::psbt::PartiallySignedTransaction,
) -> bitcoin::psbt::PartiallySignedTransaction {
    bincode::deserialize(&bincode::serialize(psbt).expect("Failed to serialize bitcoin29 psbt"))
        .expect("Failed to convert bitcoin29 psbt to bitcoin30 psbt")
}

pub fn bitcoin30_to_bitcoin29_psbt(
    psbt: &bitcoin::psbt::PartiallySignedTransaction,
) -> bitcoin29::util::psbt::PartiallySignedTransaction {
    bincode::deserialize(&bincode::serialize(psbt).expect("Failed to serialize bitcoin30 psbt"))
        .expect("Failed to convert bitcoin30 psbt to bitcoin29 psbt")
}

pub fn bitcoin29_to_bitcoin30_network_magic(magic: u32) -> bitcoin::network::Magic {
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
    bitcoin::network::Magic::from_bytes(bytes)
}

pub fn bitcoin30_to_bitcoin29_network_magic(magic: &bitcoin::network::Magic) -> u32 {
    let bytes = magic.to_bytes();
    // Invert the byte order when converting from v0.30 to v0.29.
    // See the following bitcoin v0.29 and v0.30 code:
    // https://docs.rs/bitcoin/0.29.2/src/bitcoin/network/constants.rs.html#81-84
    // https://docs.rs/bitcoin/0.30.2/src/bitcoin/network/constants.rs.html#251-258
    ((bytes[3] as u32) << 24)
        | ((bytes[2] as u32) << 16)
        | ((bytes[1] as u32) << 8)
        | (bytes[0] as u32)
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
        let bitcoin30_mainnet_magic = bitcoin::network::constants::Network::Bitcoin.magic();
        assert_eq!(
            bitcoin29_to_bitcoin30_network_magic(bitcoin29_mainnet_magic),
            bitcoin30_mainnet_magic
        );
        assert_eq!(
            bitcoin30_to_bitcoin29_network_magic(&bitcoin30_mainnet_magic),
            bitcoin29_mainnet_magic
        );

        let bitcoin29_testnet_magic: u32 = bitcoin29::network::constants::Network::Testnet.magic();
        let bitcoin30_testnet_magic = bitcoin::network::constants::Network::Testnet.magic();
        assert_eq!(
            bitcoin29_to_bitcoin30_network_magic(bitcoin29_testnet_magic),
            bitcoin30_testnet_magic
        );
        assert_eq!(
            bitcoin30_to_bitcoin29_network_magic(&bitcoin30_testnet_magic),
            bitcoin29_testnet_magic
        );

        let bitcoin29_signet_magic: u32 = bitcoin29::network::constants::Network::Signet.magic();
        let bitcoin30_signet_magic = bitcoin::network::constants::Network::Signet.magic();
        assert_eq!(
            bitcoin29_to_bitcoin30_network_magic(bitcoin29_signet_magic),
            bitcoin30_signet_magic
        );
        assert_eq!(
            bitcoin30_to_bitcoin29_network_magic(&bitcoin30_signet_magic),
            bitcoin29_signet_magic
        );

        let bitcoin29_regtest_magic: u32 = bitcoin29::network::constants::Network::Regtest.magic();
        let bitcoin30_regtest_magic = bitcoin::network::constants::Network::Regtest.magic();
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
