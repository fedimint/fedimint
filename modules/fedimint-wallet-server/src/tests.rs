use std::str::FromStr;

use bitcoin::Network::{Bitcoin, Testnet};
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, OutPoint, Txid, secp256k1};
use fedimint_core::Feerate;
use fedimint_core::encoding::btc::NetworkLegacyEncodingWrapper;
use fedimint_core::envs::is_automatic_consensus_version_voting_disabled;
use fedimint_wallet_common::{PegOut, PegOutFees, Rbf, WalletOutputV0};
use miniscript::descriptor::Wsh;

use crate::common::PegInDescriptor;
use crate::{
    CompressedPublicKey, FeeArithmetic, OsRng, SpendableUTXO, StatelessWallet, UTXOKey,
    WalletOutputError,
};

/// A peg-out recipient is chosen by the user, and nothing stops them from
/// picking the very change script the peg-out will use — change tweaks are
/// `nonce_from_idx` of a counter, so they are publicly derivable. The
/// resulting transaction carries the change script on two outputs, and
/// `recognize_change_utxo` matches on script across all of them, so it
/// tracks an output other than [`PEG_OUT_CHANGE_VOUT`]. Recording a fixed
/// change vout as claimed therefore does not cover everything `UTXOKey`
/// ends up holding; `process_input` has to reject on `UTXOKey` itself.
#[test]
fn peg_out_destination_can_collide_with_the_change_script() {
    let secp = secp256k1::Secp256k1::new();

    let descriptor = PegInDescriptor::Wsh(
        Wsh::new_sortedmulti(
            3,
            (0..4)
                .map(|_| secp.generate_keypair(&mut OsRng))
                .map(|(_, key)| CompressedPublicKey { key })
                .collect(),
        )
        .unwrap(),
    );

    let (secret_key, _) = secp.generate_keypair(&mut OsRng);

    let wallet = StatelessWallet {
        descriptor: &descriptor,
        secret_key: &secret_key,
        secp: &secp,
    };

    let change_tweak = crate::nonce_from_idx(0);
    let change_script = wallet.derive_script(&change_tweak);

    let tx = wallet
        .create_tx(
            Amount::from_sat(1000),
            change_script.clone(),
            vec![],
            vec![(
                UTXOKey(OutPoint::null()),
                SpendableUTXO {
                    tweak: [0; 33],
                    amount: bitcoin::Amount::from_sat(100_000),
                },
            )],
            Feerate { sats_per_kvb: 1000 },
            &change_tweak,
            None,
            FeeArithmetic::Checked,
        )
        .expect("tx creation succeeds");

    let matching = tx
        .psbt
        .unsigned_tx
        .output
        .iter()
        .filter(|o| o.script_pubkey == change_script)
        .count();

    assert_eq!(
        matching, 2,
        "both the destination and the change output carry the change script"
    );
}

/// Pre-2.3 the fee multiplication wrapped in release profiles, so a peg-out
/// declaring an enormous rate was accepted and broadcast with a fee too low
/// to confirm. From 2.3 on it is rejected. Both regimes must keep working:
/// replaying a pre-2.3 session has to reproduce the acceptance.
#[test]
fn fee_arithmetic_rejects_an_unpayable_rate_only_once_active() {
    let secp = secp256k1::Secp256k1::new();

    let descriptor = PegInDescriptor::Wsh(
        Wsh::new_sortedmulti(
            3,
            (0..4)
                .map(|_| secp.generate_keypair(&mut OsRng))
                .map(|(_, key)| CompressedPublicKey { key })
                .collect(),
        )
        .unwrap(),
    );

    let absurd = Feerate {
        sats_per_kvb: u64::MAX,
    };
    let ordinary = Feerate { sats_per_kvb: 1000 };

    assert_eq!(
        FeeArithmetic::Checked.calculate_fee(absurd, 958),
        Err(WalletOutputError::NotEnoughSpendableUTXO),
        "an unpayable rate is rejected once 2.3 is active"
    );
    assert_eq!(
        FeeArithmetic::Wrapping.calculate_fee(absurd, 958),
        Ok(absurd.wrapping_calculate_fee(958)),
        "pre-2.3 behaviour is reproduced exactly, wrap and all"
    );

    for arithmetic in [FeeArithmetic::Checked, FeeArithmetic::Wrapping] {
        assert_eq!(
            arithmetic.calculate_fee(ordinary, 958),
            Ok(ordinary.calculate_fee(958)),
            "an ordinary rate is unaffected in either regime"
        );
    }

    let _ = descriptor;
}

/// A peg-out amount reaches `create_tx` straight from an unauthenticated
/// caller, both via `PEG_OUT_FEES_ENDPOINT` and via a submitted peg-out
/// output. Summing it with the dust limit and the fees used to overflow
/// `bitcoin::Amount`'s panicking `Add`, killing the guardian process.
#[test]
fn create_tx_rejects_amounts_that_cannot_exist_on_chain() {
    let secp = secp256k1::Secp256k1::new();

    let descriptor = PegInDescriptor::Wsh(
        Wsh::new_sortedmulti(
            3,
            (0..4)
                .map(|_| secp.generate_keypair(&mut OsRng))
                .map(|(_, key)| CompressedPublicKey { key })
                .collect(),
        )
        .unwrap(),
    );

    let (secret_key, _) = secp.generate_keypair(&mut OsRng);

    let wallet = StatelessWallet {
        descriptor: &descriptor,
        secret_key: &secret_key,
        secp: &secp,
    };

    let recipient = Address::from_str("32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf").unwrap();
    let utxos = vec![(
        UTXOKey(OutPoint::null()),
        SpendableUTXO {
            tweak: [0; 33],
            amount: bitcoin::Amount::from_sat(100_000),
        },
    )];

    for amount in [
        Amount::from_sat(u64::MAX),
        Amount::MAX_MONEY + Amount::from_sat(1),
    ] {
        let tx = wallet.create_tx(
            amount,
            recipient.clone().assume_checked().script_pubkey(),
            vec![],
            utxos.clone(),
            Feerate { sats_per_kvb: 1000 },
            &[0; 33],
            None,
            FeeArithmetic::Checked,
        );

        assert_eq!(tx, Err(WalletOutputError::NotEnoughSpendableUTXO));
    }
}

#[test]
fn create_tx_should_validate_amounts() {
    let secp = secp256k1::Secp256k1::new();

    let descriptor = PegInDescriptor::Wsh(
        Wsh::new_sortedmulti(
            3,
            (0..4)
                .map(|_| secp.generate_keypair(&mut OsRng))
                .map(|(_, key)| CompressedPublicKey { key })
                .collect(),
        )
        .unwrap(),
    );

    let (secret_key, _) = secp.generate_keypair(&mut OsRng);

    let wallet = StatelessWallet {
        descriptor: &descriptor,
        secret_key: &secret_key,
        secp: &secp,
    };

    let spendable = SpendableUTXO {
        tweak: [0; 33],
        amount: bitcoin::Amount::from_sat(3000),
    };

    let recipient = Address::from_str("32iVBEu4dxkUQk9dJbZUiBiQdmypcEyJRf").unwrap();

    let fee = Feerate { sats_per_kvb: 1000 };
    let weight = 875;

    // not enough SpendableUTXO
    // tx fee = ceil(875 / 4) * 1 sat/vb = 219
    // change script dust = 330
    // spendable sats = 3000 - 219 - 330 = 2451
    let tx = wallet.create_tx(
        Amount::from_sat(2452),
        recipient.clone().assume_checked().script_pubkey(),
        vec![],
        vec![(UTXOKey(OutPoint::null()), spendable.clone())],
        fee,
        &[0; 33],
        None,
        FeeArithmetic::Checked,
    );
    assert_eq!(tx, Err(WalletOutputError::NotEnoughSpendableUTXO));

    // successful tx creation
    let mut tx = wallet
        .create_tx(
            Amount::from_sat(1000),
            recipient.clone().assume_checked().script_pubkey(),
            vec![],
            vec![(UTXOKey(OutPoint::null()), spendable)],
            fee,
            &[0; 33],
            None,
            FeeArithmetic::Checked,
        )
        .expect("is ok");

    // peg out weight is incorrectly set to 0
    let res = StatelessWallet::validate_tx(&tx, &rbf(fee.sats_per_kvb, 0), fee, Bitcoin);
    assert_eq!(res, Err(WalletOutputError::TxWeightIncorrect(0, weight)));

    // fee rate set below min relay fee to 0
    let res = StatelessWallet::validate_tx(&tx, &rbf(0, weight), fee, Bitcoin);
    assert_eq!(res, Err(WalletOutputError::BelowMinRelayFee));

    // fees are okay
    let res = StatelessWallet::validate_tx(&tx, &rbf(fee.sats_per_kvb, weight), fee, Bitcoin);
    assert_eq!(res, Ok(()));

    // tx has fee below consensus
    tx.fees = PegOutFees::new(0, weight);
    let res = StatelessWallet::validate_tx(&tx, &rbf(fee.sats_per_kvb, weight), fee, Bitcoin);
    assert_eq!(
        res,
        Err(WalletOutputError::PegOutFeeBelowConsensus(
            Feerate { sats_per_kvb: 0 },
            fee
        ))
    );

    // tx has peg-out amount under dust limit
    tx.peg_out_amount = bitcoin::Amount::ZERO;
    let res = StatelessWallet::validate_tx(&tx, &rbf(fee.sats_per_kvb, weight), fee, Bitcoin);
    assert_eq!(res, Err(WalletOutputError::PegOutUnderDustLimit));

    // tx is invalid for network
    let output = WalletOutputV0::PegOut(PegOut {
        recipient,
        amount: bitcoin::Amount::from_sat(1000),
        fees: PegOutFees::new(100, weight),
    });
    let res = StatelessWallet::validate_tx(&tx, &output, fee, Testnet);
    assert_eq!(
        res,
        Err(WalletOutputError::WrongNetwork(
            NetworkLegacyEncodingWrapper(Testnet),
            NetworkLegacyEncodingWrapper(Bitcoin)
        ))
    );
}

fn rbf(sats_per_kvb: u64, total_weight: u64) -> WalletOutputV0 {
    WalletOutputV0::Rbf(Rbf {
        fees: PegOutFees::new(sats_per_kvb, total_weight),
        txid: Txid::all_zeros(),
    })
}

#[test]
fn automatic_vote_suppressed_when_env_set() {
    unsafe {
        std::env::set_var("FM_WALLET_DISABLE_AUTOMATIC_CONSENSUS_VERSION_VOTING", "1");
    }
    assert!(is_automatic_consensus_version_voting_disabled());
    unsafe {
        std::env::remove_var("FM_WALLET_DISABLE_AUTOMATIC_CONSENSUS_VERSION_VOTING");
    }
}

#[test]
fn automatic_vote_active_when_env_unset() {
    unsafe {
        std::env::remove_var("FM_WALLET_DISABLE_AUTOMATIC_CONSENSUS_VERSION_VOTING");
    }
    assert!(!is_automatic_consensus_version_voting_disabled());
}
