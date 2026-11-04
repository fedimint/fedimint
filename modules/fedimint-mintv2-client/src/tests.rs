use std::collections::BTreeMap;
use std::time::Duration;

use fedimint_client_module::module::{ClientContext, ClientModule, FinalClientIface};
use fedimint_client_module::sm::ModuleNotifier;
use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::AmountUnit;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::runtime::timeout;
use fedimint_core::secp256k1::rand::thread_rng;
use fedimint_core::secp256k1::{Keypair, SECP256K1};
use fedimint_derive_secret::DerivableSecret;
use fedimint_mintv2_common::Denomination;
use fedimint_mintv2_common::config::{FeeConsensus, MintClientConfig};

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

#[tokio::test]
async fn fee_quote_does_not_wait_for_change_tweaks() {
    let db: Database = MemDatabase::new().into();
    let (module_db, access_token) = db.with_prefix_module_id(0);
    let client = FinalClientIface::default();
    // Keep the sender alive so missing tweaks remain pending.
    let (_tweak_sender, tweak_receiver) = async_channel::bounded(1);
    let mint = MintClientModule {
        federation_id: FederationId::dummy(),
        cfg: MintClientConfig {
            tbs_agg_pks: BTreeMap::new(),
            tbs_pks: BTreeMap::new(),
            fee_consensus: FeeConsensus::new(100).unwrap(),
            amount_unit: AmountUnit::BITCOIN,
        },
        root_secret: DerivableSecret::new_root(&[0; 32], &[0; 8]),
        notifier: ModuleNotifier::new(tokio::sync::broadcast::channel(1).0, 0, client.clone()),
        client_ctx: ClientContext::new(client, 0, access_token, module_db.clone()),
        balance_update_sender: tokio::sync::watch::channel(()).0,
        tweak_receiver,
    };
    let mut dbtx = module_db.begin_transaction_nc().await;
    let quote = timeout(
        Duration::from_secs(1),
        mint.quote_final_inputs_and_outputs(
            &mut dbtx.to_ref_nc(),
            OperationId::new_random(),
            AmountUnit::BITCOIN,
            Amount::from_sats(1_000),
            Amount::ZERO,
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
