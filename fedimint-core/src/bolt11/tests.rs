use std::time::Duration;

use bitcoin::Network;
use bitcoin::hashes::{Hash, sha256};
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use secp256k1::{Secp256k1, SecretKey};

use super::{currency_for_network, currency_matches_network};

const NETWORKS: [Network; 5] = [
    Network::Bitcoin,
    Network::Testnet,
    Network::Testnet4,
    Network::Signet,
    Network::Regtest,
];

const CURRENCIES: [Currency; 5] = [
    Currency::Bitcoin,
    Currency::BitcoinTestnet,
    Currency::Regtest,
    Currency::Simnet,
    Currency::Signet,
];

#[test]
fn only_matching_currency_network_pairs_are_accepted() {
    let accepted = [
        (Currency::Bitcoin, Network::Bitcoin),
        (Currency::BitcoinTestnet, Network::Testnet),
        (Currency::BitcoinTestnet, Network::Testnet4),
        (Currency::Signet, Network::Signet),
        (Currency::Regtest, Network::Regtest),
    ];

    for currency in CURRENCIES {
        for network in NETWORKS {
            assert_eq!(
                currency_matches_network(&currency, network),
                accepted.contains(&(currency.clone(), network)),
                "{currency:?} on {network:?}"
            );
        }
    }
}

#[test]
fn currency_for_network_matches_its_network() {
    for network in NETWORKS {
        assert!(
            currency_matches_network(&currency_for_network(network), network),
            "{network:?}"
        );
    }
}

#[test]
fn testnet4_invoices_use_the_testnet_prefix() {
    let secret_key = SecretKey::from_slice(&[42; 32]).expect("valid secret key");

    let invoice = InvoiceBuilder::new(currency_for_network(Network::Testnet4))
        .description(String::new())
        .payment_hash(sha256::Hash::hash(&[0; 32]))
        .payment_secret(PaymentSecret([0; 32]))
        .duration_since_epoch(Duration::from_secs(1_700_000_000))
        .min_final_cltv_expiry_delta(18)
        .amount_milli_satoshis(1_000)
        .build_signed(|msg| Secp256k1::new().sign_ecdsa_recoverable(msg, &secret_key))
        .expect("valid invoice");

    assert!(invoice.to_string().starts_with("lntb"), "{invoice}");
    assert!(currency_matches_network(
        &invoice.currency(),
        Network::Testnet4
    ));
}
