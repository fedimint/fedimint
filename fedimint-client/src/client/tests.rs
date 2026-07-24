use std::collections::BTreeMap;
use std::future::{Future, pending};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use bitcoin::key::Secp256k1;
use fedimint_api_client::api::DynGlobalApi;
use fedimint_api_client::api::global_api::with_request_hook::ApiRequestHook;
use fedimint_client_module::meta::LegacyMetaSource;
use fedimint_client_module::module::recovery::RecoveryProgress;
use fedimint_client_module::module::{ClientModuleRegistry, FinalClientIface};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::config::{
    ClientConfig, ClientModuleConfig, GlobalClientConfig, ModuleInitRegistry,
};
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::encoding::DynRawFallback;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::module::{CoreConsensusVersion, ModuleConsensusVersion};
use fedimint_core::runtime::timeout;
use fedimint_core::task::TaskGroup;
use fedimint_derive_secret::DerivableSecret;
use futures::{StreamExt as _, poll};
use tokio::select;
use tokio::sync::{broadcast, oneshot, watch};
use tokio::task::yield_now;

use super::{Client, ModuleRecoveryFuture, RecoveryStatus};
use crate::db::ClientModuleRecovery;
use crate::meta::MetaService;
use crate::oplog::OperationLog;
use crate::sm::executor::Executor;
use crate::sm::notifier::Notifier;

const FAILING_MODULE_INSTANCE_ID: ModuleInstanceId = 1;
const RECOVERING_MODULE_INSTANCE_ID: ModuleInstanceId = 2;
const RECOVERY_ERROR: &str = "module recovery went wrong";
const WAIT_TIMEOUT: Duration = Duration::from_secs(30);

struct ModuleRecoveries {
    task: Pin<Box<dyn Future<Output = ()>>>,
    status_receiver: watch::Receiver<BTreeMap<ModuleInstanceId, RecoveryStatus>>,
}

fn run_module_recoveries() -> ModuleRecoveries {
    let initial_progress = RecoveryProgress {
        complete: 0,
        total: 10,
    };

    let module_recoveries: BTreeMap<ModuleInstanceId, ModuleRecoveryFuture> = [
        (
            FAILING_MODULE_INSTANCE_ID,
            Box::pin(async { Err(anyhow!(RECOVERY_ERROR)) }) as ModuleRecoveryFuture,
        ),
        (
            RECOVERING_MODULE_INSTANCE_ID,
            Box::pin(async { Ok(None) }) as ModuleRecoveryFuture,
        ),
    ]
    .into_iter()
    .collect();

    let (progress_senders, module_recovery_progress_receivers): (Vec<_>, BTreeMap<_, _>) =
        module_recoveries
            .keys()
            .map(|module_instance_id| {
                let (progress_sender, progress_receiver) = watch::channel(initial_progress);
                (progress_sender, (*module_instance_id, progress_receiver))
            })
            .unzip();

    let module_kinds = module_recoveries
        .keys()
        .map(|module_instance_id| (*module_instance_id, ModuleKind::from_static_str("test")))
        .collect();
    let (recovery_sender, recovery_receiver) = watch::channel(
        module_recoveries
            .keys()
            .map(|module_instance_id| {
                (
                    *module_instance_id,
                    RecoveryStatus::InProgress(initial_progress),
                )
            })
            .collect(),
    );
    let (log_ordering_wakeup_tx, _log_ordering_wakeup_rx) = watch::channel(());
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());

    let task = Box::pin(async move {
        // Keep the progress streams open while the failed recovery is parked.
        let _progress_senders = progress_senders;
        Client::run_module_recoveries_task(
            db,
            log_ordering_wakeup_tx,
            recovery_sender,
            module_recoveries,
            module_recovery_progress_receivers,
            module_kinds,
        )
        .await;
    });

    ModuleRecoveries {
        task,
        status_receiver: recovery_receiver,
    }
}

async fn client_for_recovery_test(
    status_receiver: watch::Receiver<BTreeMap<ModuleInstanceId, RecoveryStatus>>,
    module_kinds: BTreeMap<ModuleInstanceId, ModuleKind>,
) -> Client {
    let modules = module_kinds
        .into_iter()
        .map(|(module_instance_id, kind)| {
            (
                module_instance_id,
                ClientModuleConfig {
                    kind,
                    version: ModuleConsensusVersion::new(0, 0),
                    config: DynRawFallback::Raw {
                        module_instance_id,
                        raw: Vec::new(),
                    },
                },
            )
        })
        .collect();
    let config = ClientConfig {
        global: GlobalClientConfig {
            api_endpoints: BTreeMap::new(),
            broadcast_public_keys: None,
            consensus_version: CoreConsensusVersion::new(0, 0),
            meta: BTreeMap::new(),
        },
        modules,
    };
    let federation_id = config.calculate_federation_id();
    let connectors = ConnectorRegistry::build_from_testing_defaults()
        .bind()
        .await
        .expect("Connector registry must build");
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let task_group = TaskGroup::new();
    let (log_ordering_wakeup_tx, _log_ordering_wakeup_rx) = watch::channel(());
    let executor = Executor::builder().build(
        db.clone(),
        Notifier::new(),
        task_group.clone(),
        log_ordering_wakeup_tx.clone(),
    );
    let (_log_event_added_tx, log_event_added_rx) = watch::channel(());
    let (log_event_added_transient_tx, _log_event_added_transient_rx) = broadcast::channel(1);
    let request_hook: ApiRequestHook = Arc::new(|api| api);

    Client {
        final_client: FinalClientIface::default(),
        config: tokio::sync::RwLock::new(config),
        api_secret: None,
        decoders: ModuleDecoderRegistry::default(),
        connectors: connectors.clone(),
        db: db.clone(),
        federation_id,
        federation_config_meta: BTreeMap::new(),
        primary_modules: BTreeMap::new(),
        modules: ClientModuleRegistry::default(),
        module_inits: ModuleInitRegistry::new(),
        executor,
        api: DynGlobalApi::new(connectors, BTreeMap::new(), None).expect("Global API must build"),
        root_secret: DerivableSecret::new_root(&[0; 32], &[0; 32]),
        operation_log: OperationLog::new(db),
        secp_ctx: Secp256k1::new(),
        meta_service: MetaService::new(LegacyMetaSource::default()),
        task_group,
        client_span: Client::make_client_span(federation_id),
        client_recovery_status_receiver: status_receiver,
        log_ordering_wakeup_tx,
        log_event_added_rx,
        log_event_added_transient_tx,
        request_hook,
        iroh_enable_dht: false,
        iroh_enable_next: false,
        user_bitcoind_rpc: None,
        user_bitcoind_rpc_no_chain_id: None,
    }
}

fn recovery_module_kinds() -> BTreeMap<ModuleInstanceId, ModuleKind> {
    [
        (
            FAILING_MODULE_INSTANCE_ID,
            ModuleKind::from_static_str("failing"),
        ),
        (
            RECOVERING_MODULE_INSTANCE_ID,
            ModuleKind::from_static_str("recovering"),
        ),
    ]
    .into_iter()
    .collect()
}

/// The recovery of a single module, driven entirely by the test.
///
/// [`Self::module_progress_sender`] is the module's own progress channel, the
/// one handed to a module as `ClientModuleRecoverArgs::progress_tx`. Sending on
/// it directly is exactly what a module bypassing `update_recovery_progress`
/// does, so it is how a test forges a progress the sanctioned API would drop.
struct SingleModuleRecovery {
    task: Pin<Box<dyn Future<Output = ()>>>,
    db: Database,
    module_progress_sender: watch::Sender<RecoveryProgress>,
    status_receiver: watch::Receiver<BTreeMap<ModuleInstanceId, RecoveryStatus>>,
}

fn run_single_module_recovery(
    initial_progress: RecoveryProgress,
    recovery: ModuleRecoveryFuture,
) -> SingleModuleRecovery {
    let (module_progress_sender, module_progress_receiver) = watch::channel(initial_progress);
    let (recovery_sender, status_receiver) = watch::channel(
        [(
            FAILING_MODULE_INSTANCE_ID,
            RecoveryStatus::InProgress(initial_progress),
        )]
        .into_iter()
        .collect(),
    );
    let (log_ordering_wakeup_tx, _log_ordering_wakeup_rx) = watch::channel(());
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());

    let task = Box::pin(Client::run_module_recoveries_task(
        db.clone(),
        log_ordering_wakeup_tx,
        recovery_sender,
        [(FAILING_MODULE_INSTANCE_ID, recovery)]
            .into_iter()
            .collect(),
        [(FAILING_MODULE_INSTANCE_ID, module_progress_receiver)]
            .into_iter()
            .collect(),
        [(
            FAILING_MODULE_INSTANCE_ID,
            ModuleKind::from_static_str("failing"),
        )]
        .into_iter()
        .collect(),
    ));

    SingleModuleRecovery {
        task,
        db,
        module_progress_sender,
        status_receiver,
    }
}

/// Poll the recovery task until it has consumed everything available to it.
///
/// The task is never spawned, so the test owns every interleaving: once the
/// task has no more work it stays pending however often it is polled, which
/// makes this a deterministic alternative to waiting for a while.
async fn drive_recovery_task(task: &mut Pin<Box<dyn Future<Output = ()>>>) {
    /// Comfortably above the handful of polls a single update needs to travel
    /// through the merged streams, the database and back out on the status
    /// channel. Polling a task with nothing left to do is free, so erring high
    /// costs nothing.
    const POLLS: usize = 16;

    for _ in 0..POLLS {
        assert!(
            poll!(task.as_mut()).is_pending(),
            "Recovery task must not finish"
        );
        yield_now().await;
    }
}

/// [`RecoveryProgress`] isn't `PartialEq`, so compare it as a tuple.
fn progress_tuple(progress: RecoveryProgress) -> (u32, u32) {
    (progress.complete, progress.total)
}

/// The progress a module's status reports, whichever state it is in.
fn status_progress_tuple(
    statuses: &watch::Receiver<BTreeMap<ModuleInstanceId, RecoveryStatus>>,
    module_instance_id: ModuleInstanceId,
) -> (u32, u32) {
    progress_tuple(statuses.borrow()[&module_instance_id].progress())
}

async fn persisted_recovery_progress(db: &Database) -> Option<RecoveryProgress> {
    db.begin_transaction_nc()
        .await
        .get_value(&ClientModuleRecovery {
            module_instance_id: FAILING_MODULE_INSTANCE_ID,
        })
        .await
        .map(|state| state.progress)
}

#[tokio::test]
async fn forged_done_recovery_progress_does_not_mask_a_later_failure() {
    // `ClientModuleRecoverArgs::progress_tx` is public, so a module can report a
    // "done" progress the sanctioned `update_recovery_progress` would drop. Such
    // a progress must never be treated as a completed recovery: only the
    // module's recovery future returning `Ok` completes one. Otherwise a failure
    // arriving later could no longer retract the success already reported, and,
    // worse, the persisted done state would make the next client startup skip
    // the recovery altogether.
    let (release_failure, failure_released) = oneshot::channel::<()>();
    let SingleModuleRecovery {
        mut task,
        db,
        module_progress_sender,
        status_receiver,
    } = run_single_module_recovery(
        RecoveryProgress {
            complete: 0,
            total: 10,
        },
        Box::pin(async move {
            // Keep the failure unobservable until the test releases it, so the
            // forged progress is all the recovery task has to go on.
            failure_released
                .await
                .expect("Release channel must stay open");
            Err(anyhow!(RECOVERY_ERROR))
        }) as ModuleRecoveryFuture,
    );
    let client = client_for_recovery_test(status_receiver.clone(), recovery_module_kinds()).await;

    // Positive control: the seeded progress has to make it all the way through
    // the task first, otherwise the assertions below would also hold for a
    // forged progress that was simply never delivered.
    drive_recovery_task(&mut task).await;
    assert_eq!(
        persisted_recovery_progress(&db).await.map(progress_tuple),
        Some((0, 10)),
        "The seeded progress must reach the recovery task"
    );

    module_progress_sender.send_replace(RecoveryProgress {
        complete: 10,
        total: 10,
    });
    drive_recovery_task(&mut task).await;

    assert_eq!(
        status_progress_tuple(&status_receiver, FAILING_MODULE_INSTANCE_ID),
        (0, 10),
        "A forged done progress must not be broadcast as a completed recovery"
    );
    assert_eq!(
        persisted_recovery_progress(&db).await.map(progress_tuple),
        Some((0, 10)),
        "A forged done progress must not be persisted, or reopening the client would skip the recovery"
    );
    let mut wait_for_all_recoveries = Box::pin(client.wait_for_all_recoveries());
    assert!(
        poll!(wait_for_all_recoveries.as_mut()).is_pending(),
        "A forged done progress must not complete the wait for all recoveries"
    );

    release_failure
        .send(())
        .expect("Recovery future must be waiting for the release");
    let error = timeout(WAIT_TIMEOUT, async {
        select! {
            () = &mut task => panic!("Recovery task must not finish"),
            result = wait_for_all_recoveries => result,
        }
    })
    .await
    .expect("Waiting on a failed module recovery must not block forever")
    .expect_err("A failure after a forged done progress must still be reported as an error")
    .to_string();

    assert!(error.contains(RECOVERY_ERROR), "{error}");
    assert!(
        error.contains(&format!("module_instance_id={FAILING_MODULE_INSTANCE_ID}")),
        "{error}"
    );
}

#[tokio::test]
async fn module_reported_none_recovery_progress_is_only_rejected_when_it_regresses() {
    let SingleModuleRecovery {
        mut task,
        db,
        module_progress_sender,
        status_receiver,
    } = run_single_module_recovery(
        RecoveryProgress::none(),
        Box::pin(pending()) as ModuleRecoveryFuture,
    );

    // A module's progress channel starts at the progress the client seeded it
    // with, so the first update every recovery reports is that seeded value.
    // Rejecting a "none" here would break normal startup.
    drive_recovery_task(&mut task).await;

    // Rejecting is inseparable from warning about a misbehaving module, so
    // seeing the seeded progress persisted covers both.
    assert_eq!(
        persisted_recovery_progress(&db).await.map(progress_tuple),
        Some(progress_tuple(RecoveryProgress::none())),
        "The client-seeded initial none progress must be accepted"
    );

    module_progress_sender.send_replace(RecoveryProgress {
        complete: 3,
        total: 10,
    });
    drive_recovery_task(&mut task).await;

    // Regressing back to "none" would throw away progress already made and
    // persisted, so it is rejected however the module reported it.
    module_progress_sender.send_replace(RecoveryProgress::none());
    drive_recovery_task(&mut task).await;

    assert_eq!(
        status_progress_tuple(&status_receiver, FAILING_MODULE_INSTANCE_ID),
        (3, 10)
    );
    assert_eq!(
        persisted_recovery_progress(&db).await.map(progress_tuple),
        Some((3, 10)),
        "Progress must stay persisted"
    );
}

#[tokio::test]
async fn wait_for_all_recoveries_reports_success_once_every_module_completed() {
    let complete_progress = RecoveryProgress {
        complete: 10,
        total: 10,
    };
    let module_kinds = recovery_module_kinds();
    // Kept alive so the wait has to succeed on the statuses themselves, rather
    // than because the channel is closed.
    let (_status_sender, status_receiver) = watch::channel(
        module_kinds
            .keys()
            .map(|module_instance_id| {
                (
                    *module_instance_id,
                    RecoveryStatus::InProgress(complete_progress),
                )
            })
            .collect(),
    );
    let client = client_for_recovery_test(status_receiver, module_kinds).await;

    timeout(WAIT_TIMEOUT, client.wait_for_all_recoveries())
        .await
        .expect("Completed recoveries must not block the wait")
        .expect("Completed recoveries must be reported as a success");
}

#[tokio::test]
async fn wait_for_all_recoveries_reports_success_without_any_recovering_module() {
    // Kept alive for the same reason as above: nothing is recovering, so the
    // wait has to succeed right away instead of waiting for an update that is
    // never coming.
    let (_status_sender, status_receiver) = watch::channel(BTreeMap::new());
    let client = client_for_recovery_test(status_receiver, recovery_module_kinds()).await;

    timeout(WAIT_TIMEOUT, client.wait_for_all_recoveries())
        .await
        .expect("A client without recoveries must not block the wait")
        .expect("A client without recoveries must be reported as a success");
}

#[tokio::test]
async fn wait_for_all_recoveries_reports_failed_module_recovery() {
    let ModuleRecoveries {
        task,
        status_receiver,
    } = run_module_recoveries();
    let client = client_for_recovery_test(status_receiver, recovery_module_kinds()).await;

    let result = timeout(WAIT_TIMEOUT, async {
        select! {
            () = task => panic!("Recovery task must not finish"),
            result = client.wait_for_all_recoveries() => result,
        }
    })
    .await
    .expect("Waiting on a failed module recovery must not block forever");
    let error = result
        .expect_err("Failed module recovery must be reported as an error")
        .to_string();

    assert!(error.contains(RECOVERY_ERROR), "{error}");
    assert!(
        error.contains(&format!("module_instance_id={FAILING_MODULE_INSTANCE_ID}")),
        "{error}"
    );
    // Reporting the failure doesn't finish the recovery: the failed module's
    // progress stays pending, which is what the progress-based observers keep
    // reporting.
    assert!(
        client.has_pending_recoveries(),
        "A failed module recovery must keep being reported as pending"
    );

    // A failed module must not silently vanish from the progress stream either:
    // it keeps being reported with the last progress it made.
    let (module_instance_id, progress) = Box::pin(client.subscribe_to_recovery_progress())
        .next()
        .await
        .expect("The progress stream must yield the current progress of every module");
    assert_eq!(module_instance_id, FAILING_MODULE_INSTANCE_ID);
    assert_eq!(
        progress_tuple(progress),
        (0, 10),
        "A failed module must keep being reported with its last progress"
    );
}

#[tokio::test]
async fn wait_for_all_recoveries_reports_a_recovery_task_that_went_away() {
    // The sender lives in the recovery task, so dropping it is what a client
    // shutting down mid-recovery looks like to a waiter. No outcome can be
    // reported anymore, which has to surface as an error rather than a hang or a
    // module failure nobody reported.
    let in_progress = RecoveryProgress {
        complete: 0,
        total: 10,
    };
    let (status_sender, status_receiver) = watch::channel(
        [(
            FAILING_MODULE_INSTANCE_ID,
            RecoveryStatus::InProgress(in_progress),
        )]
        .into_iter()
        .collect(),
    );
    let client = client_for_recovery_test(status_receiver, recovery_module_kinds()).await;

    drop(status_sender);

    let error = timeout(WAIT_TIMEOUT, client.wait_for_all_recoveries())
        .await
        .expect("A recovery task that went away must not block the wait forever")
        .expect_err("An unfinished recovery whose task went away must be reported as an error")
        .to_string();

    assert!(error.contains("disconnected"), "{error}");
    assert!(
        !error.contains("module_instance_id="),
        "A closed status channel must not be reported as a module failure: {error}"
    );
}

#[tokio::test]
async fn wait_for_module_kind_recovery_reports_matching_failure() {
    let ModuleRecoveries {
        task,
        status_receiver,
    } = run_module_recoveries();
    let module_kinds = recovery_module_kinds();
    let failing_kind = module_kinds[&FAILING_MODULE_INSTANCE_ID].clone();
    let client = client_for_recovery_test(status_receiver, module_kinds).await;

    let result = timeout(WAIT_TIMEOUT, async {
        select! {
            () = task => panic!("Recovery task must not finish"),
            result = client.wait_for_module_kind_recovery(failing_kind) => result,
        }
    })
    .await
    .expect("Waiting on a failed module recovery must not block forever");

    result.expect_err("Failure of the requested module kind must be reported");
}

#[tokio::test]
async fn wait_for_module_kind_recovery_ignores_unrelated_failure() {
    let ModuleRecoveries {
        task,
        status_receiver,
    } = run_module_recoveries();
    let module_kinds = recovery_module_kinds();
    let recovering_kind = module_kinds[&RECOVERING_MODULE_INSTANCE_ID].clone();
    let client = client_for_recovery_test(status_receiver, module_kinds).await;

    let result = timeout(WAIT_TIMEOUT, async {
        select! {
            () = task => panic!("Recovery task must not finish"),
            result = client.wait_for_module_kind_recovery(recovering_kind) => result,
        }
    })
    .await
    .expect("Waiting on a completed module recovery must not block forever");

    result.expect("Failure of an unrelated module kind must not fail the wait");
}

#[tokio::test]
async fn recovery_failure_wins_if_completion_is_also_observable() {
    // A single module can no longer be done and failed at the same time, but two
    // modules still can, and a wait covering both has to report the failure
    // rather than the completion it could just as well observe.
    let (_status_sender, status_receiver) = watch::channel(
        [
            (
                FAILING_MODULE_INSTANCE_ID,
                RecoveryStatus::Failed {
                    last_progress: RecoveryProgress {
                        complete: 0,
                        total: 10,
                    },
                    error: RECOVERY_ERROR.to_string(),
                },
            ),
            (
                RECOVERING_MODULE_INSTANCE_ID,
                RecoveryStatus::InProgress(RecoveryProgress {
                    complete: 10,
                    total: 10,
                }),
            ),
        ]
        .into_iter()
        .collect(),
    );
    let client = client_for_recovery_test(status_receiver, recovery_module_kinds()).await;

    let error = timeout(WAIT_TIMEOUT, client.wait_for_all_recoveries())
        .await
        .expect("Recovery outcome must be determinate")
        .expect_err("A recovery failure must take precedence over a completed recovery")
        .to_string();

    assert!(error.contains(RECOVERY_ERROR), "{error}");
    assert!(
        error.contains(&format!("module_instance_id={FAILING_MODULE_INSTANCE_ID}")),
        "{error}"
    );
}

#[tokio::test]
async fn failed_status_is_not_overwritten_by_late_module_progress() {
    // Progress and completion are merged without any ordering between them, so a
    // module's progress update can still arrive after its recovery already
    // failed. Applying it would replace the recorded failure with an in-progress
    // status, and a waiter subscribing afterwards would block forever again,
    // which is the very hang a determinate failure exists to prevent.
    let initial_progress = RecoveryProgress {
        complete: 0,
        total: 10,
    };
    let (release_failure, failure_released) = oneshot::channel::<()>();
    let SingleModuleRecovery {
        mut task,
        db,
        module_progress_sender,
        status_receiver,
    } = run_single_module_recovery(
        initial_progress,
        Box::pin(async move {
            // Held back so the seeded progress is processed first, which makes
            // the update below the late one.
            failure_released
                .await
                .expect("Release channel must stay open");
            Err(anyhow!(RECOVERY_ERROR))
        }) as ModuleRecoveryFuture,
    );

    // Positive control: an update of this module does reach the recovery task
    // through this very channel, so the assertions below can't hold merely
    // because the late update was never delivered.
    drive_recovery_task(&mut task).await;
    assert_eq!(
        persisted_recovery_progress(&db).await.map(progress_tuple),
        Some(progress_tuple(initial_progress)),
        "The seeded progress must reach the recovery task"
    );

    release_failure
        .send(())
        .expect("Recovery future must be waiting for the release");
    drive_recovery_task(&mut task).await;
    assert!(
        matches!(
            status_receiver.borrow()[&FAILING_MODULE_INSTANCE_ID],
            RecoveryStatus::Failed { .. }
        ),
        "The failed recovery must be recorded before the late update is delivered"
    );

    module_progress_sender.send_replace(RecoveryProgress {
        complete: 5,
        total: 10,
    });
    drive_recovery_task(&mut task).await;

    match &status_receiver.borrow()[&FAILING_MODULE_INSTANCE_ID] {
        RecoveryStatus::Failed {
            last_progress,
            error,
        } => {
            assert_eq!(
                progress_tuple(*last_progress),
                progress_tuple(initial_progress),
                "A late progress update must not advance a failed recovery"
            );
            assert!(error.contains(RECOVERY_ERROR), "{error}");
        }
        RecoveryStatus::InProgress(_) => {
            panic!("A late progress update must not erase a recorded recovery failure")
        }
    }
    assert_eq!(
        persisted_recovery_progress(&db).await.map(progress_tuple),
        Some(progress_tuple(initial_progress)),
        "A late progress update of a failed module must not be persisted"
    );

    // Subscribing only now is what makes this determinate: a waiter that missed
    // the failure as it happened still has to learn about it from the status.
    let client = client_for_recovery_test(status_receiver, recovery_module_kinds()).await;
    let error = timeout(WAIT_TIMEOUT, async {
        select! {
            () = &mut task => panic!("Recovery task must not finish"),
            result = client.wait_for_all_recoveries() => result,
        }
    })
    .await
    .expect("A late waiter on a failed module recovery must not block forever")
    .expect_err("A late waiter must still be told about the failed module recovery")
    .to_string();

    assert!(error.contains(RECOVERY_ERROR), "{error}");
    assert!(
        error.contains(&format!("module_instance_id={FAILING_MODULE_INSTANCE_ID}")),
        "{error}"
    );
}

#[tokio::test]
async fn wait_for_module_kind_recovery_reports_failure_despite_other_kind_failing() {
    // Two modules of different kinds fail, one after the other. A single-slot
    // signal would let the second failure overwrite the first, so a waiter
    // asking about the first kind would neither observe a matching failure nor
    // see its progress become done, and would block forever. Keeping a status
    // per module keeps the per-kind wait determinate, even for a waiter that
    // subscribes only after both updates happened.
    const OTHER_FAILING_MODULE_INSTANCE_ID: ModuleInstanceId = 3;

    let in_progress = RecoveryProgress {
        complete: 0,
        total: 10,
    };
    let (status_sender, _status_receiver) =
        watch::channel::<BTreeMap<ModuleInstanceId, RecoveryStatus>>(
            [
                (
                    FAILING_MODULE_INSTANCE_ID,
                    RecoveryStatus::InProgress(in_progress),
                ),
                (
                    OTHER_FAILING_MODULE_INSTANCE_ID,
                    RecoveryStatus::InProgress(in_progress),
                ),
            ]
            .into_iter()
            .collect(),
        );

    status_sender.send_modify(|statuses| {
        statuses.insert(
            FAILING_MODULE_INSTANCE_ID,
            RecoveryStatus::Failed {
                last_progress: in_progress,
                error: RECOVERY_ERROR.to_string(),
            },
        );
    });
    // The failure of the requested kind is now the value a waiter would have had
    // to be listening for, and this update of an unrelated module is what
    // replaces it as the latest one sent.
    status_sender.send_modify(|statuses| {
        statuses.insert(
            OTHER_FAILING_MODULE_INSTANCE_ID,
            RecoveryStatus::Failed {
                last_progress: in_progress,
                error: "other module recovery went wrong".to_string(),
            },
        );
    });

    let failing_kind = ModuleKind::from_static_str("failing");
    let module_kinds = [
        (FAILING_MODULE_INSTANCE_ID, failing_kind.clone()),
        (
            OTHER_FAILING_MODULE_INSTANCE_ID,
            ModuleKind::from_static_str("other"),
        ),
    ]
    .into_iter()
    .collect();
    // Subscribing only now: everything this waiter can go on is the shared map.
    let client = client_for_recovery_test(status_sender.subscribe(), module_kinds).await;

    let error = timeout(
        WAIT_TIMEOUT,
        client.wait_for_module_kind_recovery(failing_kind),
    )
    .await
    .expect("Waiting on a failed module recovery must not block forever")
    .expect_err("Failure of the requested kind must be reported despite an unrelated failure")
    .to_string();

    assert!(error.contains(RECOVERY_ERROR), "{error}");
    assert!(
        error.contains(&format!("module_instance_id={FAILING_MODULE_INSTANCE_ID}")),
        "{error}"
    );
}
