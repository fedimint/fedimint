use std::collections::{BTreeMap, BTreeSet};

use fedimint_api_client::api::global_api::with_cache::GlobalFederationApiWithCache;
use fedimint_api_client::api::{DynModuleApi, IModuleFederationApi, IRawFederationApi};
use fedimint_client_module::module::FinalClientIface;
use fedimint_client_module::module::init::recovery::RecoveryFromHistoryCommon;
use fedimint_connectors::{DynGuaridianConnection, ServerResult};
use fedimint_core::config::FederationId;
use fedimint_core::encoding::Encodable;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::{NumPeers, PeerId};

use crate::backup::WalletRecoveryState;
use crate::{
    ApiVersion, BitcoinRpcConfig, BoxStream, ClientContext, ClientModuleInit,
    ClientModuleRecoverArgs, Database, DerivableSecret, FeeConsensus,
    IDatabaseTransactionOpsCoreTyped, ModuleInstanceId, ModuleNotifier, Network,
    NextPegInTweakIndexKey, OperationId, PegInTweakIndexData, PegInTweakIndexKey,
    RecoveryFinalizedKey, RecoveryProgress, RecoveryStateKey, TaskGroup, TweakIdx,
    WalletClientConfig, WalletClientInit, apply, async_trait_maybe_send,
    recovery_already_finalized, store_recovered_peg_in_indexes, watch,
};

/// Even looking up peers must not happen after finalization.
#[derive(Debug)]
struct NoRecoveryApi;

#[apply(async_trait_maybe_send!)]
impl IRawFederationApi for NoRecoveryApi {
    fn all_peers(&self) -> &BTreeSet<PeerId> {
        panic!("finalized recovery must not query the federation")
    }

    fn self_peer(&self) -> Option<PeerId> {
        panic!("finalized recovery must not query the federation")
    }

    fn with_module(&self, _id: ModuleInstanceId) -> DynModuleApi {
        Self.into()
    }

    async fn request_raw(
        &self,
        _peer_id: PeerId,
        _method: &str,
        _params: &ApiRequestErased,
    ) -> ServerResult<serde_json::Value> {
        panic!("finalized recovery must not query the federation")
    }

    fn connection_status_stream(&self) -> BoxStream<'static, BTreeMap<PeerId, bool>> {
        panic!("finalized recovery must not query the federation")
    }

    async fn wait_for_initialized_connections(&self) {
        panic!("finalized recovery must not query the federation")
    }

    async fn get_peer_connection(&self, _peer_id: PeerId) -> ServerResult<DynGuaridianConnection> {
        panic!("finalized recovery must not query the federation")
    }
}

impl IModuleFederationApi for NoRecoveryApi {}

fn recovery_args() -> ClientModuleRecoverArgs<WalletClientInit> {
    let db = Database::new(
        fedimint_core::db::mem_impl::MemDatabase::new(),
        fedimint_core::module::registry::ModuleDecoderRegistry::default(),
    );
    let (db, token) = db.with_prefix_module_id(0);
    let client = FinalClientIface::default();
    ClientModuleRecoverArgs {
        federation_id: FederationId::dummy(),
        num_peers: NumPeers::from(1),
        cfg: WalletClientConfig {
            peg_in_descriptor:
                "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
                    .parse()
                    .unwrap(),
            network: fedimint_core::encoding::btc::NetworkLegacyEncodingWrapper(Network::Regtest),
            finality_delay: 10,
            fee_consensus: FeeConsensus::default(),
            default_bitcoin_rpc: BitcoinRpcConfig {
                kind: "esplora".to_owned(),
                url: "http://127.0.0.1:1".parse().unwrap(),
            },
        },
        db: db.clone(),
        core_api_version: ApiVersion::new(0, 0),
        module_api_version: ApiVersion::new(0, 0),
        module_root_secret: DerivableSecret::new_root(&[0; 32], &[0; 32]),
        notifier: ModuleNotifier::new(tokio::sync::broadcast::channel(1).0, 0, client.clone()),
        api: GlobalFederationApiWithCache::new(NoRecoveryApi).into(),
        admin_auth: None,
        module_api: NoRecoveryApi.into(),
        context: ClientContext::new(client, 0, token, db),
        progress_tx: watch::channel(RecoveryProgress::none()).0,
        task_group: TaskGroup::new(),
        user_bitcoind_rpc: None,
        user_bitcoind_rpc_no_chain_id: None,
    }
}

#[tokio::test]
async fn empty_or_false_marker_is_not_finalized() {
    let db = Database::new(
        fedimint_core::db::mem_impl::MemDatabase::new(),
        fedimint_core::module::registry::ModuleDecoderRegistry::default(),
    );
    assert!(!recovery_already_finalized(&db).await);
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(&RecoveryFinalizedKey, &false).await;
    dbtx.commit_tx().await;
    assert!(!recovery_already_finalized(&db).await);
    assert!(store_recovered_peg_in_indexes(&db, vec![], TweakIdx(0)).await);
    assert!(recovery_already_finalized(&db).await);
}

#[tokio::test]
async fn true_marker_without_cursor_skips_recovery() {
    let args = recovery_args();
    let mut dbtx = args.db.begin_transaction().await;
    dbtx.insert_new_entry(&RecoveryFinalizedKey, &true).await;
    dbtx.commit_tx().await;

    assert!(recovery_already_finalized(&args.db).await);
    WalletClientInit::default()
        .recover(&args, None)
        .await
        .unwrap();
    assert!(!store_recovered_peg_in_indexes(&args.db, vec![], TweakIdx(0)).await);
    assert_eq!(
        args.db
            .begin_transaction_nc()
            .await
            .get_value(&NextPegInTweakIndexKey)
            .await,
        None
    );
}

#[tokio::test]
async fn finalized_recovery_skips_history_and_api_preserving_records() {
    for marker in [None, Some(false), Some(true)] {
        let args = recovery_args();
        let mut entry = recovered_entry(1).1;
        entry.claimed.push(bitcoin::OutPoint::null());
        let state = (
            WalletRecoveryState::Default {
                variant: 42,
                bytes: vec![],
            },
            RecoveryFromHistoryCommon::new(0, 0, 10),
        );
        let mut dbtx = args.db.begin_transaction().await;
        dbtx.insert_new_entry(&PegInTweakIndexKey(TweakIdx(1)), &entry)
            .await;
        dbtx.insert_new_entry(&NextPegInTweakIndexKey, &TweakIdx(7))
            .await;
        dbtx.insert_new_entry(&RecoveryStateKey, &state).await;
        if let Some(marker) = marker {
            dbtx.insert_new_entry(&RecoveryFinalizedKey, &marker).await;
        }
        dbtx.commit_tx().await;

        assert!(recovery_already_finalized(&args.db).await);
        WalletClientInit::default()
            .recover(&args, None)
            .await
            .unwrap();
        // The lower-level finalizer must also leave legacy results untouched.
        assert!(
            !store_recovered_peg_in_indexes(&args.db, vec![recovered_entry(1)], TweakIdx(2)).await
        );
        let mut dbtx = args.db.begin_transaction_nc().await;
        assert_eq!(
            dbtx.get_value(&PegInTweakIndexKey(TweakIdx(1)))
                .await
                .unwrap()
                .consensus_encode_to_vec(),
            entry.consensus_encode_to_vec()
        );
        assert_eq!(
            dbtx.get_value(&NextPegInTweakIndexKey).await,
            Some(TweakIdx(7))
        );
        assert_eq!(dbtx.get_value(&RecoveryFinalizedKey).await, marker);
        assert_eq!(
            dbtx.get_value(&RecoveryStateKey)
                .await
                .unwrap()
                .consensus_encode_to_vec(),
            state.consensus_encode_to_vec()
        );
    }
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
    let db = Database::new(
        fedimint_core::db::mem_impl::MemDatabase::new(),
        fedimint_core::module::registry::ModuleDecoderRegistry::default(),
    );
    let mut entries = vec![recovered_entry(0), recovered_entry(1)];
    entries[0].1.claimed.push(bitcoin::OutPoint::null());

    assert!(store_recovered_peg_in_indexes(&db, entries.clone(), TweakIdx(2)).await);
    assert!(!store_recovered_peg_in_indexes(&db, vec![recovered_entry(0)], TweakIdx(99)).await);

    let mut dbtx = db.begin_transaction_nc().await;
    for (idx, entry) in entries {
        assert_eq!(
            dbtx.get_value(&PegInTweakIndexKey(idx))
                .await
                .unwrap()
                .consensus_encode_to_vec(),
            entry.consensus_encode_to_vec()
        );
    }
    assert_eq!(
        dbtx.get_value(&NextPegInTweakIndexKey).await,
        Some(TweakIdx(2))
    );
    assert_eq!(dbtx.get_value(&RecoveryFinalizedKey).await, Some(true));
    assert!(recovery_already_finalized(&db).await);
}
