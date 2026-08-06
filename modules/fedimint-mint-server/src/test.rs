use assert_matches::assert_matches;
use fedimint_core::config::{ClientModuleConfig, ServerModuleConfig};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::{Amount, BitcoinHash, InPoint, OutPoint, PeerId, TransactionId, secp256k1};
use fedimint_mint_common::config::FeeConsensus;
use fedimint_mint_common::{BlindNonce, MintInput, MintOutput, Nonce, Note};
use fedimint_server_core::{ConfigGenModuleArgs, ServerModule, ServerModuleInit};
use tbs::{BlindingKey, Message, blind_message};

use crate::db::{BlindNonceKey, RecoveryBlindNonceOutpointKey};
use crate::{Mint, MintConfig, MintConfigConsensus, MintConfigPrivate, MintInit};

const MINTS: u16 = 5;

fn build_configs() -> (Vec<ServerModuleConfig>, ClientModuleConfig) {
    let peers = (0..MINTS).map(PeerId::from).collect::<Vec<_>>();
    let args = ConfigGenModuleArgs {
        network: bitcoin::Network::Regtest,
        disable_base_fees: false,
    };
    let mint_cfg = MintInit.trusted_dealer_gen(&peers, &args);
    let client_cfg = ClientModuleConfig::from_typed(
        0,
        MintInit::kind(),
        ModuleConsensusVersion::new(0, 0),
        MintInit
            .get_client_config(&mint_cfg[&PeerId::from(0)].consensus)
            .unwrap(),
    )
    .unwrap();

    (mint_cfg.into_values().collect(), client_cfg)
}

#[test_log::test]
#[should_panic(expected = "Own key not found among pub keys.")]
fn test_new_panic_without_own_pub_key() {
    let (mint_server_cfg1, _) = build_configs();
    let (mint_server_cfg2, _) = build_configs();

    Mint::new(MintConfig {
        consensus: MintConfigConsensus {
            peer_tbs_pks: mint_server_cfg2[0]
                .to_typed::<MintConfig>()
                .unwrap()
                .consensus
                .peer_tbs_pks,
            fee_consensus: FeeConsensus::new(1000).expect("Relative fee is within range"),
            max_notes_per_denomination: 0,
        },
        private: MintConfigPrivate {
            tbs_sks: mint_server_cfg1[0]
                .to_typed::<MintConfig>()
                .unwrap()
                .private
                .tbs_sks,
        },
    });
}

fn issue_note(
    server_cfgs: &[ServerModuleConfig],
    denomination: Amount,
) -> (secp256k1::Keypair, Note) {
    let note_key = secp256k1::Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());
    let nonce = Nonce(note_key.public_key());
    let message = nonce.to_message();
    let blinding_key = tbs::BlindingKey::random();
    let blind_msg = blind_message(message, blinding_key);

    let bsig_shares = (0_u64..)
        .zip(server_cfgs.iter().map(|cfg| {
            let sks = *cfg
                .to_typed::<MintConfig>()
                .unwrap()
                .private
                .tbs_sks
                .get(denomination)
                .expect("Mint cannot issue a note of this denomination");
            tbs::sign_message(blind_msg, sks)
        }))
        .take(server_cfgs.len() - ((server_cfgs.len() - 1) / 3))
        .collect();

    let blind_signature = tbs::aggregate_signature_shares(&bsig_shares);
    let signature = tbs::unblind_signature(blinding_key, blind_signature);

    (note_key, Note { nonce, signature })
}

#[test_log::test(tokio::test)]
async fn test_detect_double_spends() {
    let (mint_server_cfg, _) = build_configs();
    let mint = Mint::new(mint_server_cfg[0].to_typed().unwrap());
    let (_, tiered) = mint
        .cfg
        .consensus
        .peer_tbs_pks
        .first_key_value()
        .expect("mint has peers");
    let highest_denomination = *tiered.max_tier();
    let (_, note) = issue_note(&mint_server_cfg, highest_denomination);

    // Normal spend works
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let input = MintInput::new_v0(highest_denomination, note);

    // Double spend in same session is detected
    let mut dbtx = db.begin_transaction_nc().await;
    mint.process_input(
        &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
        &input,
        InPoint {
            txid: TransactionId::all_zeros(),
            in_idx: 0,
        },
    )
    .await
    .expect("Spend of valid e-cash works");
    assert_matches!(
        mint.process_input(
            &mut dbtx.to_ref_with_prefix_module_id(42).0.into_nc(),
            &input,
            InPoint {
                txid: TransactionId::all_zeros(),
                in_idx: 0
            },
        )
        .await,
        Err(_)
    );
}

// Regression test for #8582 / v0.11.1: when two outputs in a single consensus
// batch share a blind nonce, `process_output` used to panic on
// `insert_new_entry(RecoveryBlindNonceOutpointKey, _)`. The fix in #8533
// switched both call sites to `insert_entry`, so the second writer must just
// warn and continue. Note that `RecoveryBlindNonceOutpointKey` ends up holding
// the *second* outpoint (last-writer wins) — the #8533 commit message claims
// "first-writer wins" but `insert_entry` overwrites, matching #8537's "the old
// outpoint is quietly lost from the recovery index" review note.
#[test_log::test(tokio::test)]
async fn test_duplicate_blind_nonce_in_process_output_does_not_panic() {
    let (mint_server_cfg, _) = build_configs();
    let mint = Mint::new(mint_server_cfg[0].to_typed().unwrap());

    let (_, tiered) = mint
        .cfg
        .consensus
        .peer_tbs_pks
        .first_key_value()
        .expect("mint has peers");
    let denomination = *tiered.max_tier();

    let blind_nonce = BlindNonce(blind_message(
        Message::from_bytes(b"dup-blind-nonce-test"),
        BlindingKey::random(),
    ));
    let output = MintOutput::new_v0(denomination, blind_nonce);

    let out_point_first = OutPoint {
        txid: TransactionId::all_zeros(),
        out_idx: 0,
    };
    let out_point_second = OutPoint {
        txid: TransactionId::all_zeros(),
        out_idx: 1,
    };

    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let mut dbtx = db.begin_transaction().await;
    let mut module_dbtx = dbtx.to_ref_with_prefix_module_id(42).0.into_nc();

    mint.process_output(&mut module_dbtx, &output, out_point_first)
        .await
        .expect("first output is accepted");

    // Pre-fix this call would panic on `insert_new_entry`; post-fix it must
    // succeed and just warn.
    mint.process_output(&mut module_dbtx, &output, out_point_second)
        .await
        .expect("duplicate blind nonce must not panic");

    assert_eq!(
        module_dbtx.get_value(&BlindNonceKey(blind_nonce)).await,
        Some(()),
        "blind nonce should be marked as used"
    );
    assert_eq!(
        module_dbtx
            .get_value(&RecoveryBlindNonceOutpointKey(blind_nonce))
            .await,
        Some(out_point_second),
        "recovery index is overwritten by the second writer (last-writer wins)"
    );
}
