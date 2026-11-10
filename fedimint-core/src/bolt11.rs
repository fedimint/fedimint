//! Mapping between Bitcoin networks and BOLT11 invoice currencies.
//!
//! BOLT11 uses the `tb` prefix for both testnet3 and testnet4, so
//! [`Currency::BitcoinTestnet`](lightning_invoice::Currency::BitcoinTestnet)
//! cannot be converted back to a single [`Network`](bitcoin::Network). The
//! `From` conversions in `lightning-invoice` are lossy in both directions
//! (`Network::Testnet4` becomes `Currency::Regtest`), so use these helpers
//! instead.

use bitcoin::Network;
use lightning_invoice::Currency;

/// Returns the BOLT11 currency used for invoices on `network`.
pub fn currency_for_network(network: Network) -> Currency {
    match network {
        Network::Bitcoin => Currency::Bitcoin,
        Network::Testnet | Network::Testnet4 => Currency::BitcoinTestnet,
        Network::Signet => Currency::Signet,
        Network::Regtest => Currency::Regtest,
    }
}

/// Returns whether an invoice in `currency` can be paid on `network`.
pub fn currency_matches_network(currency: &Currency, network: Network) -> bool {
    match currency {
        Currency::Bitcoin => network == Network::Bitcoin,
        Currency::BitcoinTestnet => matches!(network, Network::Testnet | Network::Testnet4),
        Currency::Signet => network == Network::Signet,
        Currency::Regtest => network == Network::Regtest,
        Currency::Simnet => false,
    }
}

#[cfg(test)]
mod tests;
