use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fedimint_api_client::api::{DynGlobalApi, FederationResult, StatusResponse};
use fedimint_core::admin_client::{
    ConfigGenConnectionsRequest, ConfigGenParamsRequest, ServerStatus,
};
use fedimint_core::config::ServerModuleConfigGenParamsRegistry;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::IRawDatabaseExt;
use fedimint_core::module::ApiAuth;
use fedimint_core::runtime::spawn;
use fedimint_core::task::{sleep, TaskGroup};
use fedimint_core::util::SafeUrl;
use fedimint_core::Amount;
use fedimint_dummy_common::config::{
    DummyConfig, DummyGenParams, DummyGenParamsConsensus, DummyGenParamsLocal,
};
use fedimint_dummy_server::DummyInit;
use fedimint_logging::TracingSetup;
use fedimint_portalloc::port_alloc;
use fedimint_server::config::api::ConfigGenSettings;
use fedimint_server::config::io::{read_server_config, PLAINTEXT_PASSWORD};
use fedimint_server::config::{ServerConfig, DEFAULT_MAX_CLIENT_CONNECTIONS};
use fedimint_server::core::{DynServerModuleInit, ServerModuleInit, ServerModuleInitRegistry};
use fedimint_server::net::api::ApiSecrets;
use fedimint_testing_core::test_dir;
use futures::future::join_all;
use itertools::Itertools;
use tracing::info;

/// Helper in config API tests for simulating a guardian's client and server
struct TestConfigApi {
    client: DynGlobalApi,
    auth: ApiAuth,
    name: String,
    settings: ConfigGenSettings,
    amount: Amount,
    dir: PathBuf,
}

impl TestConfigApi {
    /// Creates a new test API taking up a port, with P2P endpoint on the
    /// next port
    fn new(port: u16, name_suffix: u16, data_dir: &Path) -> TestConfigApi {
        let db = MemDatabase::new().into_database();

        let name = format!("peer{name_suffix}");
        let api_bind = format!("127.0.0.1:{port}").parse().expect("parses");
        let api_url: SafeUrl = format!("ws://127.0.0.1:{port}").parse().expect("parses");
        let p2p_bind = format!("127.0.0.1:{}", port + 1).parse().expect("parses");
        let p2p_url = format!("fedimint://127.0.0.1:{}", port + 1)
            .parse()
            .expect("parses");
        let module_inits = ServerModuleInitRegistry::from_iter([DummyInit.into()]);
        let mut modules = ServerModuleConfigGenParamsRegistry::default();
        modules.attach_config_gen_params_by_id(0, DummyInit::kind(), DummyGenParams::default());

        let default_params = ConfigGenParamsRequest {
            meta: BTreeMap::new(),
            modules,
        };
        let settings = ConfigGenSettings {
            download_token_limit: None,
            p2p_bind,
            api_bind,
            p2p_url,
            api_url: api_url.clone(),
            default_params,
            max_connections: DEFAULT_MAX_CLIENT_CONNECTIONS,
            registry: ServerModuleInitRegistry::from(vec![DynServerModuleInit::from(DummyInit)]),
        };

        let dir = data_dir.join(name_suffix.to_string());
        fs::create_dir_all(dir.clone()).expect("Unable to create test dir");

        let dir_clone = dir.clone();
        let settings_clone = settings.clone();

        spawn("fedimint server", async move {
            fedimint_server::run(
                dir_clone,
                ApiSecrets::none(),
                settings_clone,
                db,
                "dummyversionhash".to_owned(),
                &module_inits,
                TaskGroup::new(),
            )
            .await
            .expect("Failed to run fedimint server");
        });

        // our id doesn't really exist at this point
        let auth = ApiAuth(format!("password-{port}"));
        let client = DynGlobalApi::from_pre_peer_id_admin_endpoint(api_url, &None);

        TestConfigApi {
            client,
            auth,
            name,
            settings,
            amount: Amount::from_sats(u64::from(port)),
            dir,
        }
    }

    /// Helper function using generated urls
    async fn set_connections(&self, leader: &Option<SafeUrl>) -> FederationResult<()> {
        self.client
            .set_config_gen_connections(
                ConfigGenConnectionsRequest {
                    our_name: self.name.clone(),
                    leader_api_url: leader.clone(),
                },
                self.auth.clone(),
            )
            .await
    }

    /// Helper for getting server status
    async fn status(&self) -> StatusResponse {
        loop {
            match self.client.status().await {
                Ok(status) => return status,
                Err(_) => sleep(Duration::from_millis(1000)).await,
            }
            info!(
                target: fedimint_logging::LOG_TEST,
                "Test retrying server status"
            );
        }
    }

    /// Helper for awaiting all servers have the status
    /// Use this BEFORE server config gen params have been set
    async fn wait_status_preconfig(&self, status: ServerStatus, peers: &Vec<TestConfigApi>) {
        loop {
            let server_status = self.status().await.server;
            if server_status == status {
                for peer in peers {
                    let peer_status = peer.status().await.server;
                    if peer_status != server_status {
                        info!(
                            target: fedimint_logging::LOG_TEST,
                            "Test retrying peer server status preconfig"
                        );
                        sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                }
                break;
            }
            info!(
                target: fedimint_logging::LOG_TEST,
                "Test retrying server status preconfig"
            );
        }
    }

    /// Helper for awaiting all servers have the status
    /// Use this AFTER server config gen params have been set
    async fn wait_status(&self, status: ServerStatus) {
        loop {
            let response = self.client.consensus_config_gen_params().await.unwrap();
            let mismatched: Vec<_> = response
                .consensus
                .peers
                .iter()
                .filter(|(_, param)| param.status != Some(status.clone()))
                .collect();
            if mismatched.is_empty() {
                break;
            }
            info!(
                target: fedimint_logging::LOG_TEST,
                "Test retrying server status"
            );
            sleep(Duration::from_millis(10)).await;
        }
    }

    /// Sets local param to name and unique consensus amount for testing
    async fn set_config_gen_params(&self) {
        let mut modules = ServerModuleConfigGenParamsRegistry::default();
        modules.attach_config_gen_params_by_id(
            0,
            DummyInit::kind(),
            DummyGenParams {
                local: DummyGenParamsLocal,
                consensus: DummyGenParamsConsensus {
                    tx_fee: self.amount,
                },
            },
        );
        let request = ConfigGenParamsRequest {
            meta: BTreeMap::from([("\"test\"".to_string(), self.name.clone())]),
            modules,
        };

        self.client
            .set_config_gen_params(request, self.auth.clone())
            .await
            .unwrap();
    }

    /// reads the dummy module config from the filesystem
    fn read_config(&self) -> ServerConfig {
        let auth = fs::read_to_string(self.dir.join(PLAINTEXT_PASSWORD));
        read_server_config(&auth.unwrap(), &self.dir).unwrap()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_config_api() {
    const PEER_NUM: u16 = 4;
    const PORTS_PER_PEER: u16 = 2;
    let _ = TracingSetup::default().init();
    let (data_dir, _maybe_tmp_dir_guard) = test_dir("test-config-api");
    let base_port = port_alloc(PEER_NUM * PORTS_PER_PEER).unwrap();

    let mut followers = vec![];
    let mut test_config = TestConfigApi::new(base_port, 0, &data_dir);

    for i in 1..PEER_NUM {
        let port = base_port + (i * PORTS_PER_PEER);
        let follower = TestConfigApi::new(port, i, &data_dir);
        followers.push(follower);
    }

    test_config = validate_leader_setup(test_config).await;

    // Setup followers and send connection info
    for follower in &mut followers {
        assert_eq!(
            follower.status().await.server,
            ServerStatus::AwaitingPassword
        );
        follower
            .client
            .set_password(follower.auth.clone())
            .await
            .unwrap();
        let leader_url = Some(test_config.settings.api_url.clone());
        follower.set_connections(&leader_url).await.unwrap();
        follower.name = format!("{}_", follower.name);
        follower.set_connections(&leader_url).await.unwrap();
        follower.set_config_gen_params().await;
    }

    // Validate we can do a full fedimint setup
    validate_full_setup(test_config, followers).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // TODO: flaky https://github.com/fedimint/fedimint/issues/4308
async fn test_restart_setup() {
    const PEER_NUM: u16 = 4;
    const PORTS_PER_PEER: u16 = 2;
    let _ = TracingSetup::default().init();
    let (data_dir, _maybe_tmp_dir_guard) = test_dir("test-restart-setup");
    let base_port = port_alloc(PEER_NUM * PORTS_PER_PEER).unwrap();

    let mut followers = vec![];
    let mut test_config = TestConfigApi::new(base_port, 0, &data_dir);

    for i in 1..PEER_NUM {
        let port = base_port + (i * PORTS_PER_PEER);
        let follower = TestConfigApi::new(port, i, &data_dir);
        followers.push(follower);
    }

    test_config = validate_leader_setup(test_config).await;

    // Setup followers and send connection info
    for follower in &mut followers {
        assert_eq!(
            follower.status().await.server,
            ServerStatus::AwaitingPassword
        );
        follower
            .client
            .set_password(follower.auth.clone())
            .await
            .unwrap();
        let leader_url = Some(test_config.settings.api_url.clone());
        follower.set_connections(&leader_url).await.unwrap();
        follower.name = format!("{}_", follower.name);
        follower.set_connections(&leader_url).await.unwrap();
        follower.set_config_gen_params().await;
    }
    test_config
        .wait_status(ServerStatus::SharingConfigGenParams)
        .await;

    // Leader can trigger a setup restart
    test_config
        .client
        .restart_federation_setup(test_config.auth.clone())
        .await
        .unwrap();

    // All peers can trigger a setup restart. This has to be done manually by each
    // peer, and any peer could trigger a restart before the leader does.
    for peer in &followers {
        peer.client
            .restart_federation_setup(peer.auth.clone())
            .await
            .ok();
    }

    // Ensure all servers have restarted
    test_config
        .wait_status_preconfig(ServerStatus::SetupRestarted, &followers)
        .await;
    test_config
        .wait_status_preconfig(ServerStatus::AwaitingPassword, &followers)
        .await;

    test_config = validate_leader_setup(test_config).await;

    // Setup followers and send connection info
    for follower in &mut followers {
        assert_eq!(
            follower.status().await.server,
            ServerStatus::AwaitingPassword
        );
        follower
            .client
            .set_password(follower.auth.clone())
            .await
            .unwrap();
        let leader_url = Some(test_config.settings.api_url.clone());
        follower.set_connections(&leader_url).await.unwrap();
        follower.set_config_gen_params().await;
    }

    // Validate we can do a full fedimint setup after a restart
    validate_full_setup(test_config, followers).await;
}

// Validate steps when leader initiates fedimint setup
async fn validate_leader_setup(mut leader: TestConfigApi) -> TestConfigApi {
    assert_eq!(leader.status().await.server, ServerStatus::AwaitingPassword);

    // Cannot set the password twice
    leader
        .client
        .set_password(leader.auth.clone())
        .await
        .unwrap();
    assert!(leader
        .client
        .set_password(leader.auth.clone())
        .await
        .is_err());

    // We can call this twice to change the leader name
    leader.set_connections(&None).await.unwrap();
    leader.name = "leader".to_string();
    leader.set_connections(&None).await.unwrap();

    // Leader sets the config
    let _ = leader
        .client
        .get_default_config_gen_params(leader.auth.clone())
        .await
        .unwrap();
    leader.set_config_gen_params().await;

    leader
}

// Validate we can use the config api to do a full fedimint setup
async fn validate_full_setup(leader: TestConfigApi, mut followers: Vec<TestConfigApi>) {
    // Confirm we can get peer servers if we are the leader
    let peers = leader.client.get_config_gen_peers().await.unwrap();
    let names: Vec<_> = peers.into_iter().map(|peer| peer.name).sorted().collect();
    assert_eq!(names, vec!["leader", "peer1_", "peer2_", "peer3_"]);

    leader
        .wait_status(ServerStatus::SharingConfigGenParams)
        .await;

    // Followers can fetch configs
    let mut configs = vec![];
    for peer in &followers {
        configs.push(peer.client.consensus_config_gen_params().await.unwrap());
    }
    // Confirm all consensus configs are the same
    let mut consensus: Vec<_> = configs.iter().map(|p| p.consensus.clone()).collect();
    consensus.dedup();
    assert_eq!(consensus.len(), 1);
    // Confirm all peer ids are unique
    let ids: BTreeSet<_> = configs.iter().map(|p| p.our_current_id).collect();
    assert_eq!(ids.len(), followers.len());

    // all peers run DKG
    let leader_amount = leader.amount;
    let leader_name = leader.name.clone();
    followers.push(leader);
    let all_peers = Arc::new(followers);
    let (results, ()) = tokio::join!(
        join_all(
            all_peers
                .iter()
                .map(|peer| peer.client.run_dkg(peer.auth.clone()))
        ),
        all_peers[0].wait_status(ServerStatus::VerifyingConfigs)
    );
    for result in results {
        result.expect("DKG failed");
    }

    // verify config hashes equal for all peers
    let mut hashes = HashSet::new();
    for peer in all_peers.iter() {
        peer.wait_status(ServerStatus::VerifyingConfigs).await;
        hashes.insert(
            peer.client
                .get_verify_config_hash(peer.auth.clone())
                .await
                .unwrap(),
        );
    }
    assert_eq!(hashes.len(), 1);

    // set verified configs
    for peer in all_peers.iter() {
        peer.client.verified_configs(peer.auth.clone()).await.ok();
    }

    // start consensus
    for peer in all_peers.iter() {
        peer.client.start_consensus(peer.auth.clone()).await.ok();
    }

    sleep(Duration::from_secs(5)).await;

    for peer in all_peers.iter() {
        assert_eq!(peer.status().await.server, ServerStatus::ConsensusRunning);

        // verify the local and consensus values for peers
        let cfg = peer.read_config(); // read persisted configs
        let dummy: DummyConfig = cfg.get_module_config_typed(0).unwrap();
        assert_eq!(dummy.consensus.tx_fee, leader_amount);
        assert_eq!(cfg.consensus.meta["\"test\""], leader_name);
    }
}
