use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};

use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::registry::ModuleDecoderRegistry;

use super::{
    Database, DatabaseError, NextPegInTweakIndexKey, OperationId, PegInTweakIndexData,
    RecoveryFinalizedKey, SupportsSafeDepositKey, TweakIdx, recovery_already_finalized,
    store_recovered_peg_in_indexes, store_supports_safe_deposit, supports_safe_deposit_verified,
};
use crate::backup::{
    RECOVER_NUM_IDX_ADD_TO_LAST_USED, RecoverScanOutcome, recover_scan_idxes_for_activity,
};

#[allow(clippy::too_many_lines)] // shut-up clippy, it's a test
#[tokio::test(flavor = "multi_thread")]
async fn sanity_test_recover_inner() {
    {
        let last_checked = AtomicBool::new(false);
        let last_checked = &last_checked;
        assert_eq!(
            recover_scan_idxes_for_activity(TweakIdx(0), &BTreeSet::new(), |cur_idx| async move {
                Ok(match cur_idx {
                    TweakIdx(9) => {
                        last_checked.store(true, Ordering::SeqCst);
                        vec![]
                    }
                    TweakIdx(10) => panic!("Shouldn't happen"),
                    TweakIdx(11) => {
                        vec![0usize] /* just for type inference */
                    }
                    _ => vec![],
                })
            })
            .await
            .unwrap(),
            RecoverScanOutcome {
                last_used_idx: None,
                new_start_idx: TweakIdx(RECOVER_NUM_IDX_ADD_TO_LAST_USED),
                tweak_idxes_with_pegins: BTreeSet::from([])
            }
        );
        assert!(last_checked.load(Ordering::SeqCst));
    }

    {
        let last_checked = AtomicBool::new(false);
        let last_checked = &last_checked;
        assert_eq!(
            recover_scan_idxes_for_activity(
                TweakIdx(0),
                &BTreeSet::from([TweakIdx(1), TweakIdx(2)]),
                |cur_idx| async move {
                    Ok(match cur_idx {
                        TweakIdx(1) => panic!("Shouldn't happen: already used (1)"),
                        TweakIdx(2) => panic!("Shouldn't happen: already used (2)"),
                        TweakIdx(11) => {
                            last_checked.store(true, Ordering::SeqCst);
                            vec![]
                        }
                        TweakIdx(12) => panic!("Shouldn't happen"),
                        TweakIdx(13) => {
                            vec![0usize] /* just for type inference */
                        }
                        _ => vec![],
                    })
                }
            )
            .await
            .unwrap(),
            RecoverScanOutcome {
                last_used_idx: Some(TweakIdx(2)),
                new_start_idx: TweakIdx(2 + RECOVER_NUM_IDX_ADD_TO_LAST_USED),
                tweak_idxes_with_pegins: BTreeSet::from([])
            }
        );
        assert!(last_checked.load(Ordering::SeqCst));
    }

    {
        let last_checked = AtomicBool::new(false);
        let last_checked = &last_checked;
        assert_eq!(
            recover_scan_idxes_for_activity(TweakIdx(10), &BTreeSet::new(), |cur_idx| async move {
                Ok(match cur_idx {
                    TweakIdx(10) => vec![()],
                    TweakIdx(19) => {
                        last_checked.store(true, Ordering::SeqCst);
                        vec![]
                    }
                    TweakIdx(20) => panic!("Shouldn't happen"),
                    _ => vec![],
                })
            })
            .await
            .unwrap(),
            RecoverScanOutcome {
                last_used_idx: Some(TweakIdx(10)),
                new_start_idx: TweakIdx(10 + RECOVER_NUM_IDX_ADD_TO_LAST_USED),
                tweak_idxes_with_pegins: BTreeSet::from([TweakIdx(10)])
            }
        );
        assert!(last_checked.load(Ordering::SeqCst));
    }

    assert_eq!(
        recover_scan_idxes_for_activity(TweakIdx(0), &BTreeSet::new(), |cur_idx| async move {
            Ok(match cur_idx {
                TweakIdx(6 | 15) => vec![()],
                _ => vec![],
            })
        })
        .await
        .unwrap(),
        RecoverScanOutcome {
            last_used_idx: Some(TweakIdx(15)),
            new_start_idx: TweakIdx(15 + RECOVER_NUM_IDX_ADD_TO_LAST_USED),
            tweak_idxes_with_pegins: BTreeSet::from([TweakIdx(6), TweakIdx(15)])
        }
    );
    assert_eq!(
        recover_scan_idxes_for_activity(TweakIdx(10), &BTreeSet::new(), |cur_idx| async move {
            Ok(match cur_idx {
                TweakIdx(8) => {
                    vec![()] /* for type inference only */
                }
                TweakIdx(9) => {
                    panic!("Shouldn't happen")
                }
                _ => vec![],
            })
        })
        .await
        .unwrap(),
        RecoverScanOutcome {
            last_used_idx: None,
            new_start_idx: TweakIdx(9 + RECOVER_NUM_IDX_ADD_TO_LAST_USED),
            tweak_idxes_with_pegins: BTreeSet::from([])
        }
    );
    assert_eq!(
        recover_scan_idxes_for_activity(TweakIdx(10), &BTreeSet::new(), |cur_idx| async move {
            Ok(match cur_idx {
                TweakIdx(9) => panic!("Shouldn't happen"),
                TweakIdx(15) => vec![()],
                _ => vec![],
            })
        })
        .await
        .unwrap(),
        RecoverScanOutcome {
            last_used_idx: Some(TweakIdx(15)),
            new_start_idx: TweakIdx(15 + RECOVER_NUM_IDX_ADD_TO_LAST_USED),
            tweak_idxes_with_pegins: BTreeSet::from([TweakIdx(15)])
        }
    );
}

#[tokio::test]
async fn store_supports_safe_deposit_tolerates_a_lost_race() {
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());

    // Both opened before the competing write below, so committing either
    // of them must run into a write conflict.
    let racing_dbtx = db.begin_transaction().await;
    let mut sibling_dbtx = db.begin_transaction().await;

    let mut competing_dbtx = db.begin_transaction().await;
    competing_dbtx
        .insert_entry(&SupportsSafeDepositKey, &())
        .await;
    competing_dbtx.commit_tx().await;

    // Proves the setup: a plain commit of the stale sibling is rejected.
    sibling_dbtx
        .insert_entry(&SupportsSafeDepositKey, &())
        .await;
    assert!(matches!(
        sibling_dbtx.commit_tx_result().await,
        Err(DatabaseError::WriteConflict)
    ));

    store_supports_safe_deposit(racing_dbtx).await;

    assert!(supports_safe_deposit_verified(&db).await);
}

fn recovered_entry(tweak_idx: u8) -> (TweakIdx, PegInTweakIndexData) {
    (
        TweakIdx(u64::from(tweak_idx)),
        PegInTweakIndexData {
            operation_id: OperationId([tweak_idx; 32]),
            creation_time: fedimint_core::time::now(),
            last_check_time: None,
            next_check_time: Some(fedimint_core::time::now()),
            claimed: vec![],
        },
    )
}

/// The client records a module's recovery as done only after `recover()`
/// returns, so a crash in between reruns recovery with the previous run's keys
/// already written. That rerun used to hit `insert_new_entry` on an existing
/// key and panic, on that open and every one after.
#[tokio::test]
async fn recovery_rerun_after_an_interrupted_finalize_writes_nothing() {
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
    let entries = vec![recovered_entry(0), recovered_entry(1)];

    assert!(store_recovered_peg_in_indexes(&db, entries.clone(), TweakIdx(2)).await);
    assert!(!store_recovered_peg_in_indexes(&db, entries, TweakIdx(2)).await);

    let mut dbtx = db.begin_transaction_nc().await;
    assert_eq!(
        dbtx.get_value(&NextPegInTweakIndexKey).await,
        Some(TweakIdx(2))
    );
    assert_eq!(dbtx.get_value(&RecoveryFinalizedKey).await, Some(true));
    assert!(recovery_already_finalized(&db).await);
}
