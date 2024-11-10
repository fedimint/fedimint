use std::str::FromStr;

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
