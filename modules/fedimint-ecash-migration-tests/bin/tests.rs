use std::collections::BTreeMap;
use std::path::PathBuf;

use bls12_381::{G2Projective, Scalar};
use devimint::cmd;
use devimint::devfed::DevJitFed;
use fedimint_core::config::{FederationId, GlobalClientConfig, JsonClientConfig, JsonWithKind};
use fedimint_core::module::{CommonModuleInit, CoreConsensusVersion};
use fedimint_core::util::write_new_async;
use fedimint_core::{Amount, Tiered, runtime};
use fedimint_mint_common::config::MintClientConfig;
use fedimint_mint_common::{MintCommonInit, Nonce};
use ff::Field;
use group::Curve;
use tbs::{AggregatePublicKey, BlindingKey, SecretKeyShare, blind_message, sign_message};
use tracing::info;

const TIER_1000: Amount = Amount::from_sats(1);
const NUM_PEERS: usize = 4;
const THRESHOLD: usize = 3;

fn eval_polynomial(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    coefficients
        .iter()
        .cloned()
        .rev()
        .reduce(|acc, coefficient| acc * x + coefficient)
        .expect("We have at least one coefficient")
}

fn generate_synthetic_keyset() -> (Tiered<AggregatePublicKey>, Vec<Tiered<SecretKeyShare>>) {
    let tiers = [TIER_1000];

    let mut agg_pks = Tiered::default();
    let mut peer_sks: Vec<Tiered<SecretKeyShare>> =
        (0..NUM_PEERS).map(|_| Tiered::default()).collect();

    for tier in tiers {
        let poly: Vec<Scalar> = (0..THRESHOLD)
            .map(|_| Scalar::random(&mut rand::thread_rng()))
            .collect();

        let apk = (G2Projective::generator() * eval_polynomial(&poly, &Scalar::zero())).to_affine();
        agg_pks.insert(tier, AggregatePublicKey(apk));

        for (peer_idx, peer_sk_map) in peer_sks.iter_mut().enumerate() {
            let x = Scalar::from((peer_idx + 1) as u64);
            let sk = SecretKeyShare(eval_polynomial(&poly, &x));
            peer_sk_map.insert(tier, sk);
        }
    }

    (agg_pks, peer_sks)
}

fn issue_synthetic_note(
    tier_sks: &[Tiered<SecretKeyShare>],
    denomination: Amount,
) -> fedimint_mint_client::SpendableNote {
    let spend_key = fedimint_core::secp256k1::Keypair::new(
        fedimint_core::secp256k1::SECP256K1,
        &mut rand::thread_rng(),
    );
    let nonce = Nonce(spend_key.public_key());
    let message = nonce.to_message();
    let blinding_key = BlindingKey::random();
    let blind_msg = blind_message(message, blinding_key);

    let bsig_shares: BTreeMap<u64, _> = tier_sks
        .iter()
        .enumerate()
        .take(THRESHOLD)
        .map(|(peer_idx, tier_sk)| {
            let sk = tier_sk
                .get(denomination)
                .expect("Denomination not found in keyset");
            (peer_idx as u64, sign_message(blind_msg, *sk))
        })
        .collect();

    let blind_signature = tbs::aggregate_signature_shares(&bsig_shares);
    let signature = tbs::unblind_signature(blinding_key, blind_signature);

    fedimint_mint_client::SpendableNote {
        signature,
        spend_key,
    }
}

fn generate_spend_book(num_entries: usize) -> Vec<Nonce> {
    let mut nonces: Vec<Nonce> = (0..num_entries)
        .map(|_| {
            let keypair = fedimint_core::secp256k1::Keypair::new(
                fedimint_core::secp256k1::SECP256K1,
                &mut rand::thread_rng(),
            );
            Nonce(keypair.public_key())
        })
        .collect();

    nonces.sort();
    nonces
}

async fn write_keyset_to_file(keyset: &Tiered<AggregatePublicKey>) -> anyhow::Result<PathBuf> {
    let temp_dir = std::env::temp_dir();
    let config_path = temp_dir.join(format!("keyset_{}.json", rand::random::<u64>()));

    let mint_config = MintClientConfig {
        tbs_pks: keyset.clone(),
        fee_consensus: fedimint_mint_common::config::FeeConsensus::zero(),
        peer_tbs_pks: Default::default(),
        max_notes_per_denomination: 0,
    };

    let mut modules = BTreeMap::new();
    modules.insert(
        0,
        JsonWithKind::new(MintCommonInit::KIND, serde_json::to_value(&mint_config)?),
    );

    let client_config = JsonClientConfig {
        global: GlobalClientConfig {
            api_endpoints: Default::default(),
            broadcast_public_keys: None,
            consensus_version: CoreConsensusVersion::new(0, 0),
            meta: Default::default(),
        },
        modules,
    };

    write_new_async(&config_path, serde_json::to_string_pretty(&client_config)?).await?;
    Ok(config_path)
}

async fn write_spend_book_to_file(spend_book: &[Nonce]) -> anyhow::Result<PathBuf> {
    use fedimint_core::encoding::Encodable;

    let temp_dir = std::env::temp_dir();
    let spend_book_path = temp_dir.join(format!("spend_book_{}.txt", rand::random::<u64>()));

    let lines: Vec<String> = spend_book
        .iter()
        .map(|nonce| nonce.consensus_encode_to_hex())
        .collect();

    write_new_async(&spend_book_path, lines.join("\n")).await?;
    Ok(spend_book_path)
}

async fn write_notes_to_file(
    notes: &fedimint_core::TieredMulti<fedimint_mint_client::SpendableNote>,
) -> anyhow::Result<PathBuf> {
    let temp_dir = std::env::temp_dir();
    let notes_path = temp_dir.join(format!("notes_{}.txt", rand::random::<u64>()));

    let fed_prefix = FederationId::dummy().to_prefix();
    let oob_notes = fedimint_mint_client::OOBNotes::new(fed_prefix, notes.clone());

    write_new_async(&notes_path, oob_notes.to_string()).await?;
    Ok(notes_path)
}

async fn test_ecash_migration(dev_fed: &DevJitFed) -> anyhow::Result<()> {
    let federation = dev_fed.fed().await?;

    let client = federation
        .new_joined_client("ecash-migration-test-client")
        .await?;

    info!("Pegging in client");
    federation.pegin_client(10_000, &client).await?;

    info!("Generating synthetic keyset and spend book");
    let (origin_keyset, peer_sks) = generate_synthetic_keyset();
    let spend_book = generate_spend_book(10);

    let keyset_path = write_keyset_to_file(&origin_keyset).await?;
    let spend_book_path = write_spend_book_to_file(&spend_book).await?;

    info!("Registering transfer");
    let register_result = cmd!(
        client,
        "module",
        "ecash-migration",
        "register-transfer",
        "--origin-config",
        keyset_path.to_str().unwrap(),
        "--spend-book",
        spend_book_path.to_str().unwrap()
    )
    .out_json()
    .await?;

    let transfer_id = register_result
        .get("transfer_id")
        .expect("transfer_id not found")
        .as_u64()
        .expect("transfer_id not a number")
        .to_string();

    info!("Transfer registered with ID: {}", transfer_id);

    info!("Uploading keyset");
    cmd!(
        client,
        "module",
        "ecash-migration",
        "upload-keyset",
        "--transfer-id",
        transfer_id,
        "--origin-config",
        keyset_path.to_str().unwrap()
    )
    .out_json()
    .await?;

    info!("Uploading spend book");
    cmd!(
        client,
        "module",
        "ecash-migration",
        "upload-spend-book",
        "--transfer-id",
        transfer_id,
        "--spend-book",
        spend_book_path.to_str().unwrap(),
        "--chunk-size",
        "16"
    )
    .out_json()
    .await?;

    info!("Transfer should be activated now");
    runtime::sleep(std::time::Duration::from_secs(2)).await;

    info!("Funding transfer");
    cmd!(
        client,
        "module",
        "ecash-migration",
        "fund-transfer",
        "--transfer-id",
        transfer_id,
        "--amount",
        "10000"
    )
    .out_json()
    .await?;

    info!("Creating synthetic note to redeem");
    let note = issue_synthetic_note(&peer_sks, TIER_1000);
    let notes = fedimint_core::TieredMulti::from_iter(vec![(TIER_1000, note)]);
    let notes_path = write_notes_to_file(&notes).await?;

    info!("Redeeming origin ecash");
    let redeem_result = cmd!(
        client,
        "module",
        "ecash-migration",
        "redeem-origin-ecash",
        "--transfer-id",
        transfer_id,
        "--notes",
        tokio::fs::read_to_string(&notes_path).await?
    )
    .out_json()
    .await?;

    info!("Redemption result: {:?}", redeem_result);

    tokio::fs::remove_file(keyset_path).await?;
    tokio::fs::remove_file(spend_book_path).await?;
    tokio::fs::remove_file(notes_path).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test()
        .call(|dev_fed, _process_mgr| async move {
            test_ecash_migration(&dev_fed).await?;
            info!("Ecash migration tests completed successfully!");
            Ok(())
        })
        .await
}
