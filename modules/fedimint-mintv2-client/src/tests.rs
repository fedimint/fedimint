use std::collections::BTreeMap;
use std::time::Duration;

use fedimint_client_module::module::{ClientContext, ClientModule, FinalClientIface};
use fedimint_client_module::sm::ModuleNotifier;
use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_core::core::{Account, OperationId};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::AmountUnit;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::runtime::timeout;
use fedimint_core::secp256k1::rand::thread_rng;
use fedimint_core::secp256k1::{Keypair, SECP256K1};
use fedimint_derive_secret::DerivableSecret;
use fedimint_mintv2_common::Denomination;
use fedimint_mintv2_common::config::{FeeConsensus, MintClientConfig};

use crate::client_db::SpendableNoteKey;
use crate::{MintClientModule, SpendableNote, SpendableNoteUndecoded};

#[test]
fn spendable_note_undecoded_encodes_like_spendable_note() {
    let note = SpendableNote {
        denomination: Denomination(10),
        keypair: Keypair::new(SECP256K1, &mut thread_rng()),
        signature: tbs::Signature(bls12_381::G1Affine::generator()),
    };

    let bytes = note.consensus_encode_to_vec();

    let undecoded =
        SpendableNoteUndecoded::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("A spendable note decodes as an undecoded one");

    assert_eq!(undecoded.consensus_encode_to_vec(), bytes);
    assert_eq!(SpendableNoteUndecoded::from(note.clone()), undecoded);
    assert_eq!(undecoded.decode().expect("The signature is valid"), note);
}

/// Builds a mint client module over an in-memory database.
///
/// The returned sender must be kept alive so that missing change tweaks remain
/// pending instead of the channel being closed.
fn test_mint_module(
    fee_consensus: FeeConsensus,
) -> (MintClientModule, Database, async_channel::Sender<[u8; 16]>) {
    let db: Database = MemDatabase::new().into();
    let (module_db, access_token) = db.with_prefix_module_id(0);
    let client = FinalClientIface::default();
    let (tweak_sender, tweak_receiver) = async_channel::bounded(1);
    let mint = MintClientModule {
        federation_id: FederationId::dummy(),
        cfg: MintClientConfig {
            tbs_agg_pks: BTreeMap::new(),
            tbs_pks: BTreeMap::new(),
            fee_consensus,
            amount_unit: AmountUnit::BITCOIN,
        },
        root_secret: DerivableSecret::new_root(&[0; 32], &[0; 8]),
        notifier: ModuleNotifier::new(tokio::sync::broadcast::channel(1).0, 0, client.clone()),
        client_ctx: ClientContext::new(client, 0, access_token, module_db.clone()),
        balance_update_sender: tokio::sync::watch::channel(()).0,
        tweak_receiver,
    };

    (mint, module_db, tweak_sender)
}

#[tokio::test]
async fn fee_quote_does_not_wait_for_change_tweaks() {
    let (mint, module_db, _tweak_sender) = test_mint_module(FeeConsensus::new(100).unwrap());
    let mut dbtx = module_db.begin_transaction_nc().await;
    let quote = timeout(
        Duration::from_secs(1),
        mint.quote_final_inputs_and_outputs(
            &mut dbtx.to_ref_nc(),
            OperationId::new_random(),
            AmountUnit::BITCOIN,
            Amount::from_sats(1_000),
            Amount::ZERO,
            Account::Primary,
        ),
    )
    .await
    .expect("a quote must not wait for cryptographic change tweaks")
    .unwrap();

    assert!(quote.output_amount.get_bitcoin() > Amount::ZERO);
    assert!(quote.output_fee.get_bitcoin() > Amount::ZERO);
    assert_eq!(mint.tweak_receiver.len(), 0);
    dbtx.ignore_uncommitted();
}

/// Regression test for `rebalance` counting a note it pulls in at face value.
///
/// With the default 100 msat base fee, a wallet holding a single 1024 msat note
/// and 200 msat left over after funding used to make two 512 msat change notes
/// (2 * 612 msat including fees) out of 200 + 1024 msat, forgetting the 100
/// msat fee for spending the 1024 msat note, and then panic on the funding
/// check.
#[tokio::test]
async fn rebalance_accounts_for_input_fee_of_pulled_notes() {
    let fee_consensus = FeeConsensus::new(0).unwrap();
    let (mint, module_db, _tweak_sender) = test_mint_module(fee_consensus.clone());

    let note = SpendableNote {
        denomination: Denomination(10),
        keypair: Keypair::new(SECP256K1, &mut thread_rng()),
        signature: tbs::Signature(bls12_381::G1Affine::generator()),
    };
    assert_eq!(note.amount(), Amount::from_msats(1024));

    let mut dbtx = module_db.begin_transaction_nc().await;
    dbtx.insert_new_entry(
        &SpendableNoteKey(Account::Primary, note.clone().into()),
        &(),
    )
    .await;

    let leftover = Amount::from_msats(200);
    let (input_notes, output_denominations) = mint
        .select_inputs_and_change(
            &mut dbtx.to_ref_nc(),
            AmountUnit::BITCOIN,
            leftover,
            Amount::ZERO,
            Account::Primary,
        )
        .await
        .expect("The leftover amount needs no funding");

    assert_eq!(input_notes, vec![note]);

    let input_amount = leftover
        + input_notes
            .iter()
            .map(SpendableNote::amount)
            .sum::<Amount>();
    let input_fees = input_notes
        .iter()
        .map(|note| fee_consensus.fee(note.amount()))
        .sum::<Amount>();
    let output_amount = output_denominations
        .iter()
        .map(|d| d.amount() + fee_consensus.fee(d.amount()))
        .sum::<Amount>();

    assert!(
        output_amount + input_fees <= input_amount,
        "outputs {output_amount} plus input fees {input_fees} exceed inputs {input_amount}"
    );
    dbtx.ignore_uncommitted();
}
