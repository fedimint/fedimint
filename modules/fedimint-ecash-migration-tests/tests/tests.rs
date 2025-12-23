//! Integration tests for the ecash migration module.

use std::collections::BTreeMap;
use std::path::PathBuf;

use bls12_381::{G2Projective, Scalar};
use fedimint_api_client::api::FederationApiExt as _;
use fedimint_core::config::{GlobalClientConfig, JsonClientConfig, JsonWithKind};
use fedimint_core::module::{ApiRequestErased, CommonModuleInit, CoreConsensusVersion};
use fedimint_core::util::{NextOrPending, retry, write_new_async};
use fedimint_core::{Amount, Tiered, TieredMulti, sats};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_ecash_migration_client::{EcashMigrationClientInit, EcashMigrationClientModule};
use fedimint_ecash_migration_common::TransferId;
use fedimint_ecash_migration_common::api::{
    GET_TRANSFER_STATUS_ENDPOINT, GetTransferStatusRequest, GetTransferStatusResponse,
};
use fedimint_ecash_migration_server::EcashMigrationInit;
use fedimint_mint_client::SpendableNote;
use fedimint_mint_common::config::MintClientConfig;
use fedimint_mint_common::{MintCommonInit, Nonce};
use fedimint_testing::fixtures::Fixtures;
use ff::Field;
use group::Curve;
use tbs::{AggregatePublicKey, BlindingKey, SecretKeyShare, blind_message, sign_message};
use tracing::info;

const TIER_1: Amount = Amount::from_msats(1);
const TIER_2: Amount = Amount::from_msats(2);
const TIER_4: Amount = Amount::from_msats(4);
const TIER_8: Amount = Amount::from_msats(8);
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
    let tiers = [TIER_1, TIER_2, TIER_4, TIER_8, TIER_1000];

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
) -> SpendableNote {
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

    SpendableNote {
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

fn fixtures() -> Fixtures {
    let fixtures = Fixtures::new_primary(DummyClientInit, DummyInit);

    fixtures.with_module(EcashMigrationClientInit, EcashMigrationInit)
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

async fn wait_for_activation(
    module: &EcashMigrationClientModule,
    transfer_id: TransferId,
) -> anyhow::Result<()> {
    retry(
        "waiting for transfer activation",
        fedimint_core::util::backoff_util::aggressive_backoff(),
        || {
            let module_api = module.api().clone();
            async move {
                let request = ApiRequestErased::new(GetTransferStatusRequest { transfer_id });
                let status = module_api
                    .request_current_consensus_retry::<GetTransferStatusResponse>(
                        GET_TRANSFER_STATUS_ENDPOINT.to_string(),
                        request,
                    )
                    .await;
                if status.is_active {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Transfer not yet activated"))
                }
            }
        },
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn test_setup_liability_transfer() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_not_degraded().await;
    let client = fed.new_client().await;

    let (origin_keyset, _peer_sks) = generate_synthetic_keyset();
    let spend_book = generate_spend_book(100);

    let keyset_path = write_keyset_to_file(&origin_keyset).await?;
    let spend_book_path = write_spend_book_to_file(&spend_book).await?;

    let dummy_module = client.get_first_module::<DummyClientModule>()?;
    let (op, outpoint) = dummy_module.print_money(sats(10000)).await?;
    client
        .await_primary_bitcoin_module_output(op, outpoint)
        .await?;

    info!("Registering transfer");
    let ecash_migration_module = client.get_first_module::<EcashMigrationClientModule>()?;
    let register_op = ecash_migration_module
        .register_transfer(&keyset_path, &spend_book_path)
        .await?;

    let mut register_updates = ecash_migration_module
        .subscribe_register_transfer(register_op)
        .await?
        .into_stream();

    let transfer_id = loop {
        match register_updates.ok().await? {
            fedimint_ecash_migration_client::states::RegisterTransferState::Success {
                transfer_id,
            } => break transfer_id,
            fedimint_ecash_migration_client::states::RegisterTransferState::Failed { error } => {
                anyhow::bail!("Transfer registration failed: {error}");
            }
            _ => {}
        }
    };

    info!("Uploading keyset");
    ecash_migration_module
        .upload_keyset(transfer_id, &keyset_path)
        .await?;

    info!("Uploading spend book");
    ecash_migration_module
        .upload_spend_book(transfer_id, &spend_book_path, 16)
        .await?;

    info!("Waiting for activation");
    wait_for_activation(&ecash_migration_module, transfer_id).await?;

    info!("Transfer setup complete");

    tokio::fs::remove_file(keyset_path).await?;
    tokio::fs::remove_file(spend_book_path).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_redeem_valid_origin_ecash_note() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_not_degraded().await;
    let client = fed.new_client().await;

    let (origin_keyset, peer_sks) = generate_synthetic_keyset();
    let spend_book = generate_spend_book(10);

    let keyset_path = write_keyset_to_file(&origin_keyset).await?;
    let spend_book_path = write_spend_book_to_file(&spend_book).await?;

    let dummy_module = client.get_first_module::<DummyClientModule>()?;
    let (op, outpoint) = dummy_module.print_money(sats(10000)).await?;
    client
        .await_primary_bitcoin_module_output(op, outpoint)
        .await?;

    let note_amount = TIER_1000;
    let spendable_note = issue_synthetic_note(&peer_sks, note_amount);

    info!("Setting up transfer");
    let ecash_migration_module = client.get_first_module::<EcashMigrationClientModule>()?;
    let register_op = ecash_migration_module
        .register_transfer(&keyset_path, &spend_book_path)
        .await?;

    let mut register_updates = ecash_migration_module
        .subscribe_register_transfer(register_op)
        .await?
        .into_stream();

    let transfer_id = loop {
        match register_updates.ok().await? {
            fedimint_ecash_migration_client::states::RegisterTransferState::Success {
                transfer_id,
            } => break transfer_id,
            fedimint_ecash_migration_client::states::RegisterTransferState::Failed { error } => {
                anyhow::bail!("Transfer registration failed: {error}");
            }
            _ => {}
        }
    };

    ecash_migration_module
        .upload_keyset(transfer_id, &keyset_path)
        .await?;
    ecash_migration_module
        .upload_spend_book(transfer_id, &spend_book_path, 16)
        .await?;

    wait_for_activation(&ecash_migration_module, transfer_id).await?;

    info!("Funding transfer");
    let fund_amount = sats(10);
    let fund_op = ecash_migration_module
        .fund_transfer(transfer_id, fund_amount)
        .await?;

    let mut fund_updates = ecash_migration_module
        .subscribe_fund_transfer(fund_op)
        .await?
        .into_stream();

    loop {
        match fund_updates.ok().await? {
            fedimint_ecash_migration_client::states::FundTransferState::Success { .. } => break,
            fedimint_ecash_migration_client::states::FundTransferState::Failed { error } => {
                anyhow::bail!("Fund transfer failed: {error}");
            }
            _ => {}
        }
    }

    info!("Redeeming origin ecash");
    let notes = TieredMulti::from_iter(vec![(note_amount, spendable_note)]);
    let redeem_op = ecash_migration_module
        .redeem_origin_ecash(transfer_id, notes)
        .await?;

    let mut redeem_updates = ecash_migration_module
        .subscribe_redeem_origin_ecash(redeem_op)
        .await?
        .into_stream();

    loop {
        match redeem_updates.ok().await? {
            fedimint_ecash_migration_client::states::RedeemOriginEcashState::Success {
                amount,
                ..
            } => {
                assert_eq!(amount, note_amount);
                break;
            }
            fedimint_ecash_migration_client::states::RedeemOriginEcashState::Failed { error } => {
                anyhow::bail!("Redemption failed: {error}");
            }
            _ => {}
        }
    }

    info!("Redemption complete");

    tokio::fs::remove_file(keyset_path).await?;
    tokio::fs::remove_file(spend_book_path).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_redeem_invalid_note_fails() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_not_degraded().await;
    let client = fed.new_client().await;

    let (origin_keyset, peer_sks) = generate_synthetic_keyset();
    let spend_book = generate_spend_book(10);

    let keyset_path = write_keyset_to_file(&origin_keyset).await?;
    let spend_book_path = write_spend_book_to_file(&spend_book).await?;

    let dummy_module = client.get_first_module::<DummyClientModule>()?;
    let (op, outpoint) = dummy_module.print_money(sats(10000)).await?;
    client
        .await_primary_bitcoin_module_output(op, outpoint)
        .await?;

    let note_amount = TIER_1000;
    let wrong_note = issue_synthetic_note(&peer_sks, TIER_1);

    info!("Setting up transfer");
    let ecash_migration_module = client.get_first_module::<EcashMigrationClientModule>()?;
    let register_op = ecash_migration_module
        .register_transfer(&keyset_path, &spend_book_path)
        .await?;

    let mut register_updates = ecash_migration_module
        .subscribe_register_transfer(register_op)
        .await?
        .into_stream();

    let transfer_id = loop {
        match register_updates.ok().await? {
            fedimint_ecash_migration_client::states::RegisterTransferState::Success {
                transfer_id,
            } => break transfer_id,
            fedimint_ecash_migration_client::states::RegisterTransferState::Failed { error } => {
                anyhow::bail!("Transfer registration failed: {error}");
            }
            _ => {}
        }
    };

    ecash_migration_module
        .upload_keyset(transfer_id, &keyset_path)
        .await?;
    ecash_migration_module
        .upload_spend_book(transfer_id, &spend_book_path, 16)
        .await?;

    wait_for_activation(&ecash_migration_module, transfer_id).await?;

    let fund_amount = sats(10);
    let fund_op = ecash_migration_module
        .fund_transfer(transfer_id, fund_amount)
        .await?;

    let mut fund_updates = ecash_migration_module
        .subscribe_fund_transfer(fund_op)
        .await?
        .into_stream();

    loop {
        match fund_updates.ok().await? {
            fedimint_ecash_migration_client::states::FundTransferState::Success { .. } => break,
            fedimint_ecash_migration_client::states::FundTransferState::Failed { error } => {
                anyhow::bail!("Fund transfer failed: {error}");
            }
            _ => {}
        }
    }

    info!("Attempting to redeem invalid note");
    let notes = TieredMulti::from_iter(vec![(note_amount, wrong_note)]);
    let redeem_op = ecash_migration_module
        .redeem_origin_ecash(transfer_id, notes)
        .await?;

    let mut redeem_updates = ecash_migration_module
        .subscribe_redeem_origin_ecash(redeem_op)
        .await?
        .into_stream();

    loop {
        match redeem_updates.ok().await? {
            fedimint_ecash_migration_client::states::RedeemOriginEcashState::Success { .. } => {
                anyhow::bail!("Redemption should have failed but succeeded!");
            }
            fedimint_ecash_migration_client::states::RedeemOriginEcashState::Failed { error } => {
                assert!(
                    error.contains("rejected") || error.contains("not accepted"),
                    "Error should indicate rejection: {error}"
                );
                break;
            }
            _ => {}
        }
    }

    info!("Invalid note correctly rejected");

    tokio::fs::remove_file(keyset_path).await?;
    tokio::fs::remove_file(spend_book_path).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_redeem_beyond_amount_limit_fails() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_not_degraded().await;
    let client = fed.new_client().await;

    let (origin_keyset, peer_sks) = generate_synthetic_keyset();
    let spend_book = generate_spend_book(10);

    let keyset_path = write_keyset_to_file(&origin_keyset).await?;
    let spend_book_path = write_spend_book_to_file(&spend_book).await?;

    let dummy_module = client.get_first_module::<DummyClientModule>()?;
    let (op, outpoint) = dummy_module.print_money(sats(10000)).await?;
    client
        .await_primary_bitcoin_module_output(op, outpoint)
        .await?;

    let note_amount = TIER_1000;
    let spendable_note = issue_synthetic_note(&peer_sks, note_amount);

    info!("Setting up transfer");
    let ecash_migration_module = client.get_first_module::<EcashMigrationClientModule>()?;
    let register_op = ecash_migration_module
        .register_transfer(&keyset_path, &spend_book_path)
        .await?;

    let mut register_updates = ecash_migration_module
        .subscribe_register_transfer(register_op)
        .await?
        .into_stream();

    let transfer_id = loop {
        match register_updates.ok().await? {
            fedimint_ecash_migration_client::states::RegisterTransferState::Success {
                transfer_id,
            } => break transfer_id,
            fedimint_ecash_migration_client::states::RegisterTransferState::Failed { error } => {
                anyhow::bail!("Transfer registration failed: {error}");
            }
            _ => {}
        }
    };

    ecash_migration_module
        .upload_keyset(transfer_id, &keyset_path)
        .await?;
    ecash_migration_module
        .upload_spend_book(transfer_id, &spend_book_path, 16)
        .await?;

    wait_for_activation(&ecash_migration_module, transfer_id).await?;

    info!("Funding transfer with insufficient amount");
    let fund_amount = Amount::from_msats(100);
    let fund_op = ecash_migration_module
        .fund_transfer(transfer_id, fund_amount)
        .await?;

    let mut fund_updates = ecash_migration_module
        .subscribe_fund_transfer(fund_op)
        .await?
        .into_stream();

    loop {
        match fund_updates.ok().await? {
            fedimint_ecash_migration_client::states::FundTransferState::Success { .. } => break,
            fedimint_ecash_migration_client::states::FundTransferState::Failed { error } => {
                anyhow::bail!("Fund transfer failed: {error}");
            }
            _ => {}
        }
    }

    info!("Attempting to redeem note worth more than funded amount");
    let notes = TieredMulti::from_iter(vec![(note_amount, spendable_note)]);
    let redeem_op = ecash_migration_module
        .redeem_origin_ecash(transfer_id, notes)
        .await?;

    let mut redeem_updates = ecash_migration_module
        .subscribe_redeem_origin_ecash(redeem_op)
        .await?
        .into_stream();

    loop {
        match redeem_updates.ok().await? {
            fedimint_ecash_migration_client::states::RedeemOriginEcashState::Success { .. } => {
                anyhow::bail!("Redemption should have failed due to insufficient funds!");
            }
            fedimint_ecash_migration_client::states::RedeemOriginEcashState::Failed { error } => {
                assert!(
                    error.contains("rejected") || error.contains("not accepted"),
                    "Error should indicate rejection: {error}"
                );
                break;
            }
            _ => {}
        }
    }

    info!("Over-limit redemption correctly rejected");

    tokio::fs::remove_file(keyset_path).await?;
    tokio::fs::remove_file(spend_book_path).await?;

    Ok(())
}
