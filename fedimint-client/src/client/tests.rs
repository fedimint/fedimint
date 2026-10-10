use std::collections::BTreeMap;
use std::future::{Future, pending};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::key::Secp256k1;
use fedimint_api_client::api::DynGlobalApi;
use fedimint_api_client::api::global_api::with_request_hook::ApiRequestHook;
use fedimint_client_module::OperationId;
use fedimint_client_module::error::{
    ClientModuleError, OperationNotFoundError, TransactionSubmitError,
};
use fedimint_client_module::meta::LegacyMetaSource;
use fedimint_client_module::module::recovery::{DynModuleBackup, RecoveryProgress};
use fedimint_client_module::module::{
    ClientModuleRegistry, DynClientModule, FinalClientIface, IClientModule, PrimaryModuleSupport,
};
use fedimint_client_module::sm::DynContext;
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle, TransactionBuilder,
};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::config::{
    ClientConfig, ClientModuleConfig, GlobalClientConfig, ModuleInitRegistry,
};
use fedimint_core::core::{Decoder, IntoDynInstance as _, ModuleInstanceId, ModuleKind};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::encoding::DynRawFallback;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::module::{AmountUnit, Amounts, CoreConsensusVersion, ModuleConsensusVersion};
use fedimint_core::runtime::timeout;
use fedimint_core::task::TaskGroup;
use fedimint_core::{Amount, OutPoint};
use fedimint_derive_secret::DerivableSecret;
use futures::{StreamExt as _, poll};
use tokio::select;
use tokio::sync::{broadcast, oneshot, watch};
use tokio::task::yield_now;

use super::{Client, ModuleRecoveryFuture, RecoveryStatus};
use crate::ClientHandle;
use crate::db::ClientModuleRecovery;
use crate::error::RecoveryError;
use crate::meta::MetaService;
use crate::oplog::OperationLog;
use crate::sm::executor::Executor;
use crate::sm::notifier::Notifier;

const FAILING_MODULE_INSTANCE_ID: ModuleInstanceId = 1;
const RECOVERING_MODULE_INSTANCE_ID: ModuleInstanceId = 2;
const WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// The failure the failing module's recovery reports. A type of its own, so
/// the assertions can tell it apart from any failure the client produces.
#[derive(Debug, thiserror::Error)]
#[error("module recovery went wrong")]
struct RecoveryFailure;

/// Whether `error` is the [`RecoveryFailure`] the failing module reported.
fn is_recovery_failure(error: &ClientModuleError) -> bool {
    matches!(error, ClientModuleError::Other(source) if source.is::<RecoveryFailure>())
}

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
            Box::pin(async { Err(ClientModuleError::other(RecoveryFailure)) })
                as ModuleRecoveryFuture,
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
        .await;
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
        api: DynGlobalApi::new(connectors, BTreeMap::new(), None),
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

/// Asserts that `err` is the terminal failure of `module_instance_id`,
/// carrying the error the module's recovery failed with.
fn assert_module_recovery_failed(err: &RecoveryError, module_instance_id: ModuleInstanceId) {
    match err {
        RecoveryError::Failed {
            module_instance_id: failed,
            source,
        } => {
            assert_eq!(*failed, module_instance_id, "{err:?}");
            assert!(is_recovery_failure(source), "{source:?}");
        }
        other => panic!("Expected a failed module recovery, got {other:?}"),
    }
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
            Err(ClientModuleError::other(RecoveryFailure))
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
    .expect_err("A failure after a forged done progress must still be reported as an error");

    assert_module_recovery_failed(&error, FAILING_MODULE_INSTANCE_ID);
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
    let error = result.expect_err("Failed module recovery must be reported as an error");

    assert_module_recovery_failed(&error, FAILING_MODULE_INSTANCE_ID);
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
        .expect_err("An unfinished recovery whose task went away must be reported as an error");

    assert!(
        matches!(error, RecoveryError::ClientStopped),
        "A closed status channel must not be reported as a module failure: {error:?}"
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
                    error: Arc::new(ClientModuleError::other(RecoveryFailure)),
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
        .expect_err("A recovery failure must take precedence over a completed recovery");

    assert_module_recovery_failed(&error, FAILING_MODULE_INSTANCE_ID);
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
            Err(ClientModuleError::other(RecoveryFailure))
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
            assert!(is_recovery_failure(error), "{error:?}");
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
    .expect_err("A late waiter must still be told about the failed module recovery");

    assert_module_recovery_failed(&error, FAILING_MODULE_INSTANCE_ID);
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
                error: Arc::new(ClientModuleError::other(RecoveryFailure)),
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
                error: Arc::new(ClientModuleError::other("other module recovery went wrong")),
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
    .expect_err("Failure of the requested kind must be reported despite an unrelated failure");

    assert_module_recovery_failed(&error, FAILING_MODULE_INSTANCE_ID);
}

/// The last [`ClientHandle`] may get dropped on a thread without a tokio
/// runtime context, e.g. while unwinding from a panic on a plain thread. The
/// drop impl must fall back to a non-blocking shutdown instead of panicking,
/// which during unwind would abort the process.
///
/// <https://github.com/fedimint/fedimint/issues/9053>
#[tokio::test]
async fn client_handle_drop_outside_runtime_does_not_panic() {
    let (_status_sender, status_receiver) = watch::channel(BTreeMap::new());
    let client = client_for_recovery_test(status_receiver, BTreeMap::new()).await;
    let handle = ClientHandle::new(Arc::new(client));

    std::thread::spawn(move || drop(handle))
        .join()
        .expect("Dropping a ClientHandle outside a runtime must not panic");
}

/// A client with no modules and an empty database, enough to exercise the
/// lookups that only read the operation log.
async fn client_for_lookup_test() -> Client {
    let (_status_sender, status_receiver) = watch::channel(BTreeMap::new());
    client_for_recovery_test(status_receiver, BTreeMap::new()).await
}

#[tokio::test]
async fn operation_fees_of_a_missing_operation_are_reported_as_not_found() {
    let client = client_for_lookup_test().await;
    let operation_id = OperationId::new_random();

    let err = client
        .get_operation_fees(operation_id)
        .await
        .expect_err("An operation that was never started has no fees");

    assert_eq!(err.operation_id, operation_id);
}

#[tokio::test]
async fn visualizing_a_missing_operation_is_reported_as_not_found() {
    let client = client_for_lookup_test().await;
    let operation_id = OperationId::new_random();

    // `OperationVisData` is not `Debug`, so `expect_err` is not available here.
    let Err(err) = client.get_operations_vis(Some(operation_id), None).await else {
        panic!("An operation that was never started cannot be visualized");
    };
    let err: OperationNotFoundError = err;

    assert_eq!(err.operation_id, operation_id);
}

#[tokio::test]
async fn quoting_a_fee_without_a_primary_module_is_typed() {
    use fedimint_client_module::error::TransactionSubmitError;
    use fedimint_client_module::transaction::FeeQuoteRequest;
    use fedimint_core::module::{AmountUnit, Amounts};

    let client = client_for_lookup_test().await;

    let err = client
        .fee_quote(
            OperationId::new_random(),
            FeeQuoteRequest {
                input_amount: Amounts::ZERO,
                output_amount: Amounts::new_bitcoin(fedimint_core::Amount::from_sats(1)),
                input_fee: Amounts::ZERO,
                output_fee: Amounts::ZERO,
            },
        )
        .await
        .expect_err("A client without a primary module cannot balance a transaction");

    assert!(
        matches!(
            err,
            TransactionSubmitError::NoPrimaryModule {
                unit: AmountUnit::BITCOIN
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn an_unknown_module_instance_is_reported_as_such() {
    use fedimint_client_module::error::ModuleLookupError;

    let client = client_for_lookup_test().await;

    let err = client
        .get_module_client_dyn(7)
        .expect_err("A client without modules has no instance 7");

    assert!(
        matches!(err, ModuleLookupError::UnknownInstance { instance_id: 7 }),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_balance_without_a_primary_module_is_reported_as_such() {
    use fedimint_client_module::error::ModuleLookupError;
    use fedimint_core::module::AmountUnit;

    let client = client_for_lookup_test().await;

    let err = client
        .get_balance_for_unit(AmountUnit::BITCOIN)
        .await
        .expect_err("A client without a primary module has no balance");

    assert!(
        matches!(
            err,
            ModuleLookupError::NoPrimaryModule {
                unit: AmountUnit::BITCOIN
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn loading_a_client_secret_that_was_never_stored_is_typed() {
    use crate::error::ClientSecretError;

    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());

    let err = Client::load_decodable_client_secret::<[u8; 64]>(&db)
        .await
        .expect_err("Nothing was ever stored");

    assert!(matches!(err, ClientSecretError::NotPresent), "{err:?}");
}

#[tokio::test]
async fn storing_a_second_client_secret_is_typed() {
    use crate::error::ClientSecretError;

    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());

    Client::store_encodable_client_secret(&db, [0u8; 64])
        .await
        .expect("The first secret must be stored");
    let err = Client::store_encodable_client_secret(&db, [1u8; 64])
        .await
        .expect_err("A stored secret must not be overwritten");

    assert!(matches!(err, ClientSecretError::AlreadyExists), "{err:?}");
}

#[derive(fedimint_core::encoding::Encodable, fedimint_core::encoding::Decodable, Clone, Debug, Hash, PartialEq, Eq)]
struct TestInput;

impl std::fmt::Display for TestInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestInput")
    }
}

impl fedimint_core::core::Input for TestInput {
    const KIND: ModuleKind = ModuleKind::from_static_str("mock");
}

impl fedimint_core::core::IntoDynInstance for TestInput {
    type DynType = fedimint_core::core::DynInput;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        fedimint_core::core::DynInput::from_typed(instance_id, self)
    }
}

#[derive(fedimint_core::encoding::Encodable, fedimint_core::encoding::Decodable, Clone, Debug, Hash, PartialEq, Eq)]
struct TestOutput;

impl std::fmt::Display for TestOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestOutput")
    }
}

impl fedimint_core::core::Output for TestOutput {
    const KIND: ModuleKind = ModuleKind::from_static_str("mock");
}

impl fedimint_core::core::IntoDynInstance for TestOutput {
    type DynType = fedimint_core::core::DynOutput;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        fedimint_core::core::DynOutput::from_typed(instance_id, self)
    }
}

#[derive(Debug)]
struct MockBalanceModule {
    input_fee: Amounts,
    output_fee: Amounts,
}

#[fedimint_core::apply(fedimint_core::async_trait_maybe_send!)]
impl IClientModule for MockBalanceModule {
    fn as_any(&self) -> &(fedimint_core::maybe_add_send_sync!(dyn std::any::Any)) {
        self
    }
    fn decoder(&self) -> Decoder {
        Decoder::default()
    }
    fn context(&self, _instance: ModuleInstanceId) -> DynContext {
        unimplemented!()
    }
    async fn start(&self) {}
    async fn handle_cli_command(
        &self,
        _args: &[std::ffi::OsString],
    ) -> Result<serde_json::Value, ClientModuleError> {
        unimplemented!()
    }
    async fn handle_rpc(
        &self,
        _method: String,
        _request: serde_json::Value,
    ) -> futures::stream::BoxStream<'_, Result<serde_json::Value, ClientModuleError>> {
        unimplemented!()
    }
    fn input_fee(&self, _amount: &Amounts, _input: &fedimint_core::core::DynInput) -> Option<Amounts> {
        Some(self.input_fee.clone())
    }
    fn output_fee(&self, _amount: &Amounts, _output: &fedimint_core::core::DynOutput) -> Option<Amounts> {
        Some(self.output_fee.clone())
    }
    fn supports_backup(&self) -> bool {
        false
    }
    async fn backup(
        &self,
        _module_instance_id: ModuleInstanceId,
    ) -> Result<DynModuleBackup, ClientModuleError> {
        unimplemented!()
    }
    fn supports_being_primary(&self) -> PrimaryModuleSupport {
        PrimaryModuleSupport::None
    }
    async fn create_final_inputs_and_outputs(
        &self,
        _module_instance: ModuleInstanceId,
        _dbtx: &mut DatabaseTransaction<'_>,
        _operation_id: OperationId,
        _unit: AmountUnit,
        _input_amount: Amount,
        _output_amount: Amount,
    ) -> Result<(ClientInputBundle, ClientOutputBundle), ClientModuleError> {
        unimplemented!()
    }
    async fn await_primary_module_output(
        &self,
        _operation_id: OperationId,
        _out_point: OutPoint,
    ) -> Result<(), ClientModuleError> {
        unimplemented!()
    }
    async fn get_balance(
        &self,
        _module_instance: ModuleInstanceId,
        _dbtx: &mut DatabaseTransaction<'_>,
        _unit: AmountUnit,
    ) -> Amount {
        Amount::ZERO
    }
    async fn subscribe_balance_changes(&self) -> futures::stream::BoxStream<'static, ()> {
        unimplemented!()
    }
}

async fn client_with_mock_module(input_fee: Amounts, output_fee: Amounts) -> Client {
    let mut client = client_for_lookup_test().await;
    let mock = MockBalanceModule {
        input_fee,
        output_fee,
    };
    client.modules = ModuleRegistry::from_iter([(
        1,
        ModuleKind::from_static_str("mock"),
        DynClientModule::from(mock),
    )]);
    client
}

fn test_input_bundle(amounts: Amounts) -> ClientInputBundle {
    ClientInputBundle::new_no_sm(vec![ClientInput {
        input: TestInput,
        keys: vec![],
        amounts,
    }])
    .into_dyn(1)
}

fn test_output_bundle(amounts: Amounts) -> ClientOutputBundle {
    ClientOutputBundle::new_no_sm(vec![ClientOutput {
        output: TestOutput,
        amounts,
    }])
    .into_dyn(1)
}

#[tokio::test]
async fn transaction_builder_get_balance_empty_succeeds() {
    let client = client_for_lookup_test().await;
    let builder = TransactionBuilder::new();
    let (in_amounts, out_amounts) = client
        .transaction_builder_get_balance(&builder)
        .expect("Empty builder must have valid balance");
    assert_eq!(in_amounts, Amounts::ZERO);
    assert_eq!(out_amounts, Amounts::ZERO);
}

#[tokio::test]
async fn transaction_builder_get_balance_overflow_conditions_fail() {
    let cases = vec![
        (
            "input totals overflow",
            Amounts::ZERO,
            Amounts::ZERO,
            TransactionBuilder::new()
                .with_inputs(test_input_bundle(Amounts::new_bitcoin(Amount::from_msats(u64::MAX))))
                .with_inputs(test_input_bundle(Amounts::new_bitcoin(Amount::from_msats(1)))),
        ),
        (
            "output totals overflow",
            Amounts::ZERO,
            Amounts::ZERO,
            TransactionBuilder::new()
                .with_outputs(test_output_bundle(Amounts::new_bitcoin(Amount::from_msats(u64::MAX))))
                .with_outputs(test_output_bundle(Amounts::new_bitcoin(Amount::from_msats(1)))),
        ),
        (
            "input fees overflow",
            Amounts::new_bitcoin(Amount::from_msats(u64::MAX)),
            Amounts::ZERO,
            TransactionBuilder::new()
                .with_inputs(test_input_bundle(Amounts::ZERO))
                .with_inputs(test_input_bundle(Amounts::ZERO)),
        ),
        (
            "output fees overflow",
            Amounts::ZERO,
            Amounts::new_bitcoin(Amount::from_msats(u64::MAX)),
            TransactionBuilder::new()
                .with_outputs(test_output_bundle(Amounts::ZERO))
                .with_outputs(test_output_bundle(Amounts::ZERO)),
        ),
        (
            "output plus fees overflow",
            Amounts::ZERO,
            Amounts::new_bitcoin(Amount::from_msats(1)),
            TransactionBuilder::new()
                .with_outputs(test_output_bundle(Amounts::new_bitcoin(Amount::from_msats(u64::MAX)))),
        ),
    ];

    for (name, input_fee, output_fee, builder) in cases {
        let client = client_with_mock_module(input_fee, output_fee).await;
        let err = client
            .transaction_builder_get_balance(&builder)
            .expect_err(&format!("Case '{name}' must fail with AmountOverflow"));
        assert!(
            matches!(err, TransactionSubmitError::AmountOverflow),
            "Case '{name}' expected AmountOverflow, got {err:?}"
        );
    }
}

#[tokio::test]
async fn transaction_builder_get_balance_nonempty_maximum_valid_boundary_with_distinct_units_succeeds()
{
    let custom_unit = AmountUnit::new_custom(1);
    let client = client_with_mock_module(
        Amounts::new_bitcoin(Amount::from_msats(5)),
        Amounts::new_custom(custom_unit, Amount::from_msats(25))
            .checked_add_unit(Amount::from_msats(10), AmountUnit::BITCOIN)
            .expect("Fits in unit"),
    )
    .await;

    let mut input_amounts_1 = Amounts::new_bitcoin(Amount::from_msats(u64::MAX - 50));
    input_amounts_1 = input_amounts_1
        .checked_add_unit(Amount::from_msats(u64::MAX - 100), custom_unit)
        .expect("Fits in unit");

    let mut input_amounts_2 = Amounts::new_bitcoin(Amount::from_msats(50));
    input_amounts_2 = input_amounts_2
        .checked_add_unit(Amount::from_msats(100), custom_unit)
        .expect("Fits in unit");

    let mut output_amounts = Amounts::new_bitcoin(Amount::from_msats(u64::MAX - 20));
    output_amounts = output_amounts
        .checked_add_unit(Amount::from_msats(u64::MAX - 25), custom_unit)
        .expect("Fits in unit");

    let builder = TransactionBuilder::new()
        .with_inputs(test_input_bundle(input_amounts_1))
        .with_inputs(test_input_bundle(input_amounts_2))
        .with_outputs(test_output_bundle(output_amounts));

    let (in_amounts, out_amounts) = client
        .transaction_builder_get_balance(&builder)
        .expect("Valid boundary amounts reaching u64::MAX across distinct units must succeed");

    assert_eq!(
        in_amounts
            .get(&AmountUnit::BITCOIN)
            .copied()
            .unwrap_or_default(),
        Amount::from_msats(u64::MAX)
    );
    assert_eq!(
        in_amounts.get(&custom_unit).copied().unwrap_or_default(),
        Amount::from_msats(u64::MAX)
    );
    assert_eq!(
        out_amounts
            .get(&AmountUnit::BITCOIN)
            .copied()
            .unwrap_or_default(),
        Amount::from_msats(u64::MAX) // (u64::MAX - 20) + 2*5 input fee + 10 output fee = u64::MAX
    );
    assert_eq!(
        out_amounts.get(&custom_unit).copied().unwrap_or_default(),
        Amount::from_msats(u64::MAX) // (u64::MAX - 25) + 2*0 input fee + 25 output fee = u64::MAX
    );
}
