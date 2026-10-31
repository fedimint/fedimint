use std::panic::AssertUnwindSafe;

use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{
    DatabaseKeyPrefix, DatabaseTransaction, IDatabaseTransactionOpsCore,
    IDatabaseTransactionOpsCoreTyped, IRawDatabaseExt,
};
use fedimint_core::module::audit::Audit;
use fedimint_core::{Amount, BitcoinHash, OutPoint, TransactionId, secp256k1};
use fedimint_mint_common::Nonce;
use fedimint_server_core::ServerModule;
use futures::{FutureExt, StreamExt};

use super::build_configs;
use crate::Mint;
use crate::db::{MintAuditItemKey, MintAuditItemKeyPrefix, NonceKey};

/// The pre-optimization consolidation, kept as a differential reference.
async fn legacy_consolidate(tx: &mut DatabaseTransaction<'_>) {
    let mut issuances = Amount::ZERO;
    let mut redemptions = Amount::ZERO;
    let keys = tx
        .find_by_prefix(&MintAuditItemKeyPrefix)
        .await
        .map(|(key, value)| {
            match key {
                MintAuditItemKey::Issuance(_) | MintAuditItemKey::IssuanceTotal => {
                    issuances += value;
                }
                MintAuditItemKey::Redemption(_) | MintAuditItemKey::RedemptionTotal => {
                    redemptions += value;
                }
            }
            key
        })
        .collect::<Vec<_>>()
        .await;
    for key in keys {
        tx.remove_entry(&key).await;
    }
    tx.insert_entry(&MintAuditItemKey::IssuanceTotal, &issuances)
        .await;
    tx.insert_entry(&MintAuditItemKey::RedemptionTotal, &redemptions)
        .await;
}

#[tokio::test]
async fn audit_no_previous_matches_legacy_bytes_and_totals() {
    let (configs, _) = build_configs();
    let mint = Mint::new(configs[0].to_typed().unwrap());
    let legacy = MemDatabase::new().into_database();
    let optimized = MemDatabase::new().into_database();
    let keypair = secp256k1::Keypair::new(secp256k1::SECP256K1, &mut rand::thread_rng());
    let redemption = MintAuditItemKey::Redemption(NonceKey(Nonce(keypair.public_key())));
    for round in 0_u16..4 {
        // Round zero exercises an empty audit. Later rounds include totals
        // from previous audits and overwrite one redemption row repeatedly.
        for db in [&legacy, &optimized] {
            let mut tx = db.begin_transaction().await;
            if round != 0 {
                tx.insert_entry(
                    &MintAuditItemKey::Issuance(OutPoint {
                        txid: TransactionId::all_zeros(),
                        out_idx: u64::from(round),
                    }),
                    &Amount::from_sats(100),
                )
                .await;
                tx.insert_entry(&redemption, &Amount::from_sats(30)).await;
            }
            tx.commit_tx().await;
        }
        let mut old_tx = legacy.begin_transaction().await;
        legacy_consolidate(&mut old_tx.to_ref_nc()).await;
        let mut new_tx = optimized.begin_transaction().await;
        let mut audit = Audit::default();
        mint.audit(&mut new_tx.to_ref_nc(), &mut audit, 0).await;
        assert_eq!(
            audit.net_assets().unwrap().milli_sat,
            -70_000 * i64::from(round)
        );
        for (key, expected) in [
            (MintAuditItemKey::IssuanceTotal, 100 * u64::from(round)),
            (MintAuditItemKey::RedemptionTotal, 30 * u64::from(round)),
        ] {
            assert_eq!(
                new_tx.get_value(&key).await,
                Some(Amount::from_sats(expected))
            );
        }
        assert_eq!(
            old_tx
                .raw_find_by_prefix(&[])
                .await
                .unwrap()
                .collect::<Vec<_>>()
                .await,
            new_tx
                .raw_find_by_prefix(&[])
                .await
                .unwrap()
                .collect::<Vec<_>>()
                .await,
        );
        old_tx.commit_tx().await;
        new_tx.commit_tx().await;
    }
}

#[tokio::test]
async fn malformed_audit_rows_fail_before_mutation_and_roll_back() {
    let (configs, _) = build_configs();
    let mint = Mint::new(configs[0].to_typed().unwrap());
    for optimized in [false, true] {
        let db = MemDatabase::new().into_database();
        let mut seed = db.begin_transaction().await;
        seed.insert_entry(&MintAuditItemKey::IssuanceTotal, &Amount::from_sats(7))
            .await;
        seed.raw_insert_bytes(&MintAuditItemKey::RedemptionTotal.to_bytes(), &[])
            .await
            .unwrap();
        seed.commit_tx().await;
        let mut tx = db.begin_transaction().await;
        let before = tx
            .raw_find_by_prefix(&[])
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await;
        let failed = if optimized {
            AssertUnwindSafe(mint.audit(&mut tx.to_ref_nc(), &mut Audit::default(), 0))
                .catch_unwind()
                .await
                .is_err()
        } else {
            AssertUnwindSafe(legacy_consolidate(&mut tx.to_ref_nc()))
                .catch_unwind()
                .await
                .is_err()
        };
        assert!(failed);
        assert_eq!(
            tx.raw_find_by_prefix(&[])
                .await
                .unwrap()
                .collect::<Vec<_>>()
                .await,
            before
        );
        drop(tx);
        assert_eq!(
            db.begin_transaction()
                .await
                .raw_find_by_prefix(&[])
                .await
                .unwrap()
                .collect::<Vec<_>>()
                .await,
            before
        );
    }
}
