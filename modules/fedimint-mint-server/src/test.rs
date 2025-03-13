use assert_matches::assert_matches;
use fedimint_core::config::{
    ClientModuleConfig, ConfigGenModuleParams, EmptyGenParams, ServerModuleConfig,
};
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::{Amount, BitcoinHash, InPoint, PeerId, TransactionId, secp256k1};
use fedimint_mint_common::config::FeeConsensus;
use fedimint_mint_common::{MintInput, Nonce, Note};
use fedimint_server_core::{ServerModule, ServerModuleInit};
use tbs::blind_message;

use crate::common::config::MintGenParamsConsensus;
use crate::{
    Mint, MintConfig, MintConfigConsensus, MintConfigLocal, MintConfigPrivate, MintGenParams,
    MintInit,
};

const MINTS: u16 = 5;

fn build_configs() -> (Vec<ServerModuleConfig>, ClientModuleConfig) {
    let peers = (0..MINTS).map(PeerId::from).collect::<Vec<_>>();
    let mint_cfg = MintInit.trusted_dealer_gen(
        &peers,
        &ConfigGenModuleParams::from_typed(MintGenParams {
            local: EmptyGenParams::default(),
            consensus: MintGenParamsConsensus::new(
                2,
                FeeConsensus::new(1000).expect("Relative fee is within range"),
            ),
        })
        .unwrap(),
    );
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
        local: MintConfigLocal,
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
