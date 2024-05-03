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
