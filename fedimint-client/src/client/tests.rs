use std::collections::BTreeMap;
use std::future::Future;
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
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::encoding::DynRawFallback;
use fedimint_core::module::registry::{ModuleDecoderRegistry, ModuleRegistry};
use fedimint_core::module::{CoreConsensusVersion, ModuleConsensusVersion};
use fedimint_core::runtime::timeout;
use fedimint_core::task::TaskGroup;
use fedimint_derive_secret::DerivableSecret;
use tokio::select;
use tokio::sync::{broadcast, watch};

use super::{Client, ModuleRecoveryFuture, RecoveryFailure};
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
    progress_receiver: watch::Receiver<BTreeMap<ModuleInstanceId, RecoveryProgress>>,
    failure_receiver: watch::Receiver<BTreeMap<ModuleInstanceId, RecoveryFailure>>,
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
            .map(|module_instance_id| (*module_instance_id, initial_progress))
            .collect(),
    );
    let (recovery_failure_sender, recovery_failure_receiver) = watch::channel(BTreeMap::new());
    let (log_ordering_wakeup_tx, _log_ordering_wakeup_rx) = watch::channel(());
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());

    let task = Box::pin(async move {
        // Keep the progress streams open while the failed recovery is parked.
        let _progress_senders = progress_senders;
        Client::run_module_recoveries_task(
            db,
            log_ordering_wakeup_tx,
            recovery_sender,
            recovery_failure_sender,
            module_recoveries,
            module_recovery_progress_receivers,
            module_kinds,
        )
        .await;
    });

    ModuleRecoveries {
        task,
        progress_receiver: recovery_receiver,
        failure_receiver: recovery_failure_receiver,
    }
}

async fn client_for_recovery_test(
    progress_receiver: watch::Receiver<BTreeMap<ModuleInstanceId, RecoveryProgress>>,
    failure_receiver: watch::Receiver<BTreeMap<ModuleInstanceId, RecoveryFailure>>,
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
        client_recovery_progress_receiver: progress_receiver,
        client_recovery_failure_receiver: failure_receiver,
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

#[tokio::test]
async fn wait_for_all_recoveries_reports_failed_module_recovery() {
    let ModuleRecoveries {
        task,
        progress_receiver,
        failure_receiver,
    } = run_module_recoveries();
    let client =
        client_for_recovery_test(progress_receiver, failure_receiver, recovery_module_kinds())
            .await;

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
}

#[tokio::test]
async fn wait_for_module_kind_recovery_reports_matching_failure() {
    let ModuleRecoveries {
        task,
        progress_receiver,
        failure_receiver,
    } = run_module_recoveries();
    let module_kinds = recovery_module_kinds();
    let failing_kind = module_kinds[&FAILING_MODULE_INSTANCE_ID].clone();
    let client = client_for_recovery_test(progress_receiver, failure_receiver, module_kinds).await;

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
        progress_receiver,
        failure_receiver,
    } = run_module_recoveries();
    let module_kinds = recovery_module_kinds();
    let recovering_kind = module_kinds[&RECOVERING_MODULE_INSTANCE_ID].clone();
    let client = client_for_recovery_test(progress_receiver, failure_receiver, module_kinds).await;

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
    let complete_progress = RecoveryProgress {
        complete: 10,
        total: 10,
    };
    let (_progress_sender, progress_receiver) = watch::channel(
        [(FAILING_MODULE_INSTANCE_ID, complete_progress)]
            .into_iter()
            .collect(),
    );
    let (_failure_sender, failure_receiver) = watch::channel(
        [(
            FAILING_MODULE_INSTANCE_ID,
            RecoveryFailure {
                module_instance_id: FAILING_MODULE_INSTANCE_ID,
                error: RECOVERY_ERROR.to_string(),
            },
        )]
        .into_iter()
        .collect(),
    );
    let client =
        client_for_recovery_test(progress_receiver, failure_receiver, recovery_module_kinds())
            .await;

    timeout(WAIT_TIMEOUT, client.wait_for_all_recoveries())
        .await
        .expect("Recovery outcome must be determinate")
        .expect_err("A recovery failure must take precedence over completed progress");
}

#[tokio::test]
async fn wait_for_module_kind_recovery_reports_failure_despite_other_kind_failing() {
    // Two modules of different kinds fail. A single-slot failure signal would let
    // the second failure overwrite the first, so a waiter asking about the first
    // kind would neither observe a matching failure nor see its progress become
    // done, and would block forever. Keeping every failure keeps the per-kind
    // wait determinate.
    const OTHER_FAILING_MODULE_INSTANCE_ID: ModuleInstanceId = 3;

    let in_progress = RecoveryProgress {
        complete: 0,
        total: 10,
    };
    let (_progress_sender, progress_receiver) = watch::channel(
        [
            (FAILING_MODULE_INSTANCE_ID, in_progress),
            (OTHER_FAILING_MODULE_INSTANCE_ID, in_progress),
        ]
        .into_iter()
        .collect(),
    );
    let (_failure_sender, failure_receiver) = watch::channel(
        [
            (
                FAILING_MODULE_INSTANCE_ID,
                RecoveryFailure {
                    module_instance_id: FAILING_MODULE_INSTANCE_ID,
                    error: RECOVERY_ERROR.to_string(),
                },
            ),
            (
                OTHER_FAILING_MODULE_INSTANCE_ID,
                RecoveryFailure {
                    module_instance_id: OTHER_FAILING_MODULE_INSTANCE_ID,
                    error: "other module recovery went wrong".to_string(),
                },
            ),
        ]
        .into_iter()
        .collect(),
    );

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
    let client = client_for_recovery_test(progress_receiver, failure_receiver, module_kinds).await;

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
