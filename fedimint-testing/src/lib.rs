use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fmt::Debug;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1;
use cln_rpc::ClnRpc;
use fedimint_api::cancellable::Cancellable;
use fedimint_api::config::{
    ClientConfig, ClientModuleConfig, ModuleConfigGenParams, ServerModuleConfig,
};
use fedimint_api::core::{ConsensusItem as PerModuleConsensusItem, Decoder, PluginConsensusItem};
use fedimint_api::db::mem_impl::MemDatabase;
use fedimint_api::db::{Database, DatabaseTransaction};
use fedimint_api::encoding::ModuleRegistry;
use fedimint_api::module::interconnect::ModuleInterconect;
use fedimint_api::module::{
    ApiError, FederationModuleConfigGen, InputMeta, ModuleError, TransactionItemAmount,
};
use fedimint_api::net::peers::IMuxPeerConnections;
use fedimint_api::server::IServerModule;
use fedimint_api::task::TaskGroup;
use fedimint_api::{Amount, OutPoint, PeerId, ServerModulePlugin};
use fedimint_server::config::{connect, ServerConfig, ServerConfigParams};
use fedimint_server::epoch::ConsensusItem;
use fedimint_server::multiplexed::PeerConnectionMultiplexer;
use fedimint_server::net::connect::mock::MockNetwork;
use fedimint_server::net::connect::{Connector, TlsTcpConnector};
use fedimint_wallet::config::WalletConfig;
use futures::future::join_all;
use mint_client::api::WsFederationApi;
use mint_client::{UserClient, UserClientConfig};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::sync::Mutex;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::btc::fixtures::FakeBitcoinTest;
use crate::btc::real::RealBitcoinTest;
use crate::btc::BitcoinTest;
use crate::federation::FederationTest;
use crate::gateway::GatewayTest;
use crate::ln::fake::FakeLightningTest;
use crate::ln::real::RealLightningTest;
use crate::ln::LightningTest;
use crate::user::UserTest;
use crate::utils::LnRpcAdapter;

pub mod btc;
pub mod federation;
pub mod gateway;
pub mod ln;
pub mod user;
pub mod utils;

static BASE_PORT: AtomicU16 = AtomicU16::new(4000_u16);

// Helper functions for easier test writing
pub fn rng() -> OsRng {
    OsRng
}

pub fn msats(amount: u64) -> Amount {
    Amount::from_msat(amount)
}

pub fn sats(amount: u64) -> Amount {
    Amount::from_sat(amount)
}

pub fn sha256(data: &[u8]) -> sha256::Hash {
    bitcoin::hashes::sha256::Hash::hash(data)
}

pub fn secp() -> secp256k1::Secp256k1<secp256k1::All> {
    bitcoin::secp256k1::Secp256k1::new()
}

pub fn assert_ci<M: PluginConsensusItem>(ci: &ConsensusItem) -> &M {
    if let ConsensusItem::Module(mci) = ci {
        assert_module_ci(mci)
    } else {
        panic!("Not a module consensus item");
    }
}

pub fn assert_module_ci<M: PluginConsensusItem>(mci: &PerModuleConsensusItem) -> &M {
    mci.as_any().downcast_ref().unwrap()
}

#[non_exhaustive]
pub struct Fixtures {
    pub fed: FederationTest,
    pub user: UserTest<UserClientConfig>,
    pub bitcoin: Box<dyn BitcoinTest>,
    pub gateway: GatewayTest,
    pub lightning: Box<dyn LightningTest>,
    pub task_group: TaskGroup,
}

/// Generates the fixtures for an integration test and spawns API and HBBFT consensus threads for
/// federation nodes starting at port 4000.
pub async fn fixtures(num_peers: u16) -> anyhow::Result<Fixtures> {
    let mut task_group = TaskGroup::new();
    let base_port = BASE_PORT.fetch_add(num_peers * 10, Ordering::Relaxed);

    // in case we need to output logs using 'cargo test -- --nocapture'
    if base_port == 4000 {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("info,fedimint::consensus=warn")),
            )
            .init();
    }
    let peers = (0..num_peers as u16).map(PeerId::from).collect::<Vec<_>>();
    let params = ServerConfigParams::gen_local(
        &peers,
        Amount::from_sat(1000),
        base_port,
        "test",
        "127.0.0.1:18443",
    );
    let max_evil = hbbft::util::max_faulty(peers.len());

    match env::var("FM_TEST_DISABLE_MOCKS") {
        Ok(s) if s == "1" => {
            info!("Testing with REAL Bitcoin and Lightning services");
            let (server_config, client_config) =
                distributed_config(&peers, params, max_evil, &mut task_group)
                    .await
                    .expect("distributed config should not be canceled");

            let dir = env::var("FM_TEST_DIR").expect("Must have test dir defined for real tests");
            let wallet_config: WalletConfig = server_config
                .iter()
                .last()
                .unwrap()
                .1
                .get_module_config("wallet")
                .unwrap();
            let bitcoin_rpc = fedimint_bitcoind::bitcoincore_rpc::make_bitcoind_rpc(
                &wallet_config.btc_rpc,
                task_group.make_handle(),
            )
            .expect("Could not create bitcoinrpc");
            let bitcoin = RealBitcoinTest::new(&wallet_config.btc_rpc);
            let socket_gateway = PathBuf::from(dir.clone()).join("ln1/regtest/lightning-rpc");
            let socket_other = PathBuf::from(dir.clone()).join("ln2/regtest/lightning-rpc");
            let lightning =
                RealLightningTest::new(socket_gateway.clone(), socket_other.clone()).await;
            let gateway_lightning_rpc = Mutex::new(
                ClnRpc::new(socket_gateway.clone())
                    .await
                    .expect("connect to ln_socket"),
            );
            let lightning_rpc_adapter = LnRpcAdapter::new(Box::new(gateway_lightning_rpc));

            let connect_gen =
                |cfg: &ServerConfig| TlsTcpConnector::new(cfg.tls_config()).into_dyn();
            let fed_db = || rocks(dir.clone()).into();
            let fed = FederationTest::new(
                server_config,
                &fed_db,
                &|| bitcoin_rpc.clone(),
                &connect_gen,
                &mut task_group,
            )
            .await;

            let user_db = rocks(dir.clone()).into();
            let user_cfg = UserClientConfig(client_config.clone());
            let user = UserTest::new(Arc::new(create_user_client(user_cfg, peers, user_db).await));
            user.client.await_consensus_block_height(0).await?;

            let gateway = GatewayTest::new(
                lightning_rpc_adapter,
                client_config.clone(),
                lightning.gateway_node_pub_key,
                base_port + (2 * num_peers) + 1,
            )
            .await;

            Ok(Fixtures {
                fed,
                user,
                bitcoin: Box::new(bitcoin),
                gateway,
                lightning: Box::new(lightning),
                task_group,
            })
        }
        _ => {
            info!("Testing with FAKE Bitcoin and Lightning services");
            let (server_config, client_config) =
                ServerConfig::trusted_dealer_gen(&peers, &params, OsRng);

            let bitcoin = FakeBitcoinTest::new();
            let bitcoin_rpc = || bitcoin.clone().into();
            let lightning = FakeLightningTest::new();
            let ln_rpc_adapter = LnRpcAdapter::new(Box::new(lightning.clone()));
            let net = MockNetwork::new();
            let net_ref = &net;
            let connect_gen = move |cfg: &ServerConfig| net_ref.connector(cfg.identity).into_dyn();

            let fed_db = || MemDatabase::new().into();
            let fed = FederationTest::new(
                server_config,
                &fed_db,
                &bitcoin_rpc,
                &connect_gen,
                &mut task_group,
            )
            .await;

            let user_db = MemDatabase::new().into();
            let user_cfg = UserClientConfig(client_config.clone());
            let user = UserTest::new(Arc::new(create_user_client(user_cfg, peers, user_db).await));
            user.client.await_consensus_block_height(0).await?;

            let gateway = GatewayTest::new(
                ln_rpc_adapter,
                client_config.clone(),
                lightning.gateway_node_pub_key,
                base_port + (2 * num_peers) + 1,
            )
            .await;

            Ok(Fixtures {
                fed,
                user,
                bitcoin: Box::new(bitcoin),
                gateway,
                lightning: Box::new(lightning),
                task_group,
            })
        }
    }
}

pub fn peers(peers: &[u16]) -> Vec<PeerId> {
    peers
        .iter()
        .map(|i| PeerId::from(*i))
        .collect::<Vec<PeerId>>()
}

/// Creates a new user client connected to the given peers
pub async fn create_user_client(
    config: UserClientConfig,
    peers: Vec<PeerId>,
    db: Database,
) -> UserClient {
    let api = WsFederationApi::new(
        config
            .0
            .nodes
            .iter()
            .enumerate()
            .filter(|(id, _)| peers.contains(&PeerId::from(*id as u16)))
            .map(|(id, node)| (PeerId::from(id as u16), node.url.clone()))
            .collect(),
    )
    .into();

    UserClient::new_with_api(config, db, api, Default::default()).await
}

async fn distributed_config(
    peers: &[PeerId],
    params: HashMap<PeerId, ServerConfigParams>,
    _max_evil: usize,
    task_group: &mut TaskGroup,
) -> Cancellable<(BTreeMap<PeerId, ServerConfig>, ClientConfig)> {
    let configs: Cancellable<Vec<(PeerId, ServerConfig)>> = join_all(peers.iter().map(|peer| {
        let params = params.clone();
        let peers = peers.to_vec();

        let mut task_group = task_group.clone();

        async move {
            let our_params = params[peer].clone();
            let server_conn = connect(
                our_params.server_dkg.clone(),
                our_params.tls.clone(),
                &mut task_group,
            )
            .await;
            let connections = PeerConnectionMultiplexer::new(server_conn).into_dyn();

            let rng = OsRng;
            let cfg = ServerConfig::distributed_gen(
                &connections,
                peer,
                &peers,
                &our_params,
                rng,
                &mut task_group,
            );
            (*peer, cfg.await.expect("generation failed"))
        }
    }))
    .await
    .into_iter()
    .map(|(peer_id, maybe_cancelled)| maybe_cancelled.map(|v| (peer_id, v)))
    .collect();

    let configs = configs?;

    let (_, config) = configs.first().unwrap().clone();

    Ok((configs.into_iter().collect(), config.to_client_config()))
}

fn rocks(dir: String) -> fedimint_rocksdb::RocksDb {
    let db_dir = PathBuf::from(dir).join(format!("db-{}", rng().next_u64()));
    fedimint_rocksdb::RocksDb::open(db_dir).unwrap()
}

#[derive(Debug)]
pub struct FakeFed<Module> {
    members: Vec<(PeerId, Module, Database)>,
    client_cfg: ClientModuleConfig,
    block_height: Arc<std::sync::atomic::AtomicU64>,
}

// TODO: probably remove after modularization
#[derive(Debug, PartialEq, Eq)]
pub struct TestInputMeta {
    pub amount: TransactionItemAmount,
    pub keys: Vec<secp256k1_zkp::XOnlyPublicKey>,
}

impl<Module> FakeFed<Module>
where
    Module: ServerModulePlugin + 'static + Send + Sync,
    Module::ConsensusItem: Clone,
    Module::OutputOutcome: Eq + Debug,
    Module::Decoder: Sync + Send + 'static,
{
    pub async fn new<ConfGen, F, FF>(
        members: usize,
        constructor: F,
        params: &ModuleConfigGenParams,
        conf_gen: &ConfGen,
    ) -> anyhow::Result<FakeFed<Module>>
    where
        ConfGen: FederationModuleConfigGen,
        F: Fn(ServerModuleConfig, Database) -> FF,
        FF: Future<Output = anyhow::Result<Module>>,
    {
        let peers = (0..members)
            .map(|idx| PeerId::from(idx as u16))
            .collect::<Vec<_>>();
        let (server_cfg, client_cfg) = conf_gen.trusted_dealer_gen(&peers, params);

        let mut members = vec![];
        for (peer, cfg) in server_cfg {
            let mem_db: Database = MemDatabase::new().into();
            let member = constructor(cfg, mem_db.clone()).await?;
            members.push((peer, member, mem_db));
        }

        Ok(FakeFed {
            members,
            client_cfg,
            block_height: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn set_block_height(&self, bh: u64) {
        self.block_height.store(bh, Ordering::Relaxed);
    }

    pub async fn verify_input(&self, input: &Module::Input) -> Result<TestInputMeta, ModuleError> {
        let fake_ic = FakeInterconnect::new_block_height_responder(self.block_height.clone());

        async fn member_validate<M: ServerModulePlugin>(
            member: &M,
            dbtx: &mut DatabaseTransaction<'_>,
            fake_ic: &FakeInterconnect,
            input: &M::Input,
        ) -> Result<TestInputMeta, ModuleError> {
            let cache = member.build_verification_cache(std::iter::once(input));
            let InputMeta {
                amount,
                puk_keys: pub_keys,
            } = member.validate_input(fake_ic, dbtx, &cache, input).await?;
            Ok(TestInputMeta {
                amount,
                keys: pub_keys,
            })
        }

        let mut results = vec![];
        for (_, member, db) in &self.members {
            let mut dbtx = db.begin_transaction(self.decoders());
            results.push(member_validate(member, &mut dbtx, &fake_ic, input).await);
            dbtx.commit_tx().await.expect("DB tx failed");
        }

        assert_all_equal_result(results.into_iter())
    }

    pub async fn verify_output(&self, output: &Module::Output) -> bool {
        let mut results = Vec::new();
        for (_, member, db) in self.members.iter() {
            results.push(
                member
                    .validate_output(&mut db.begin_transaction(self.decoders()), output)
                    .await
                    .is_err(),
            );
        }
        assert_all_equal(results.into_iter())
    }

    fn decoders(&self) -> ModuleRegistry<Decoder> {
        let module = &self.members.first().unwrap().1;
        std::iter::once((module.module_key(), IServerModule::decoder(module))).collect()
    }

    // TODO: add expected result to inputs/outputs
    pub async fn consensus_round(
        &mut self,
        inputs: &[Module::Input],
        outputs: &[(OutPoint, Module::Output)],
    ) where
        <Module as ServerModulePlugin>::Input: Send + Sync,
    {
        let fake_ic = FakeInterconnect::new_block_height_responder(self.block_height.clone());
        let decoders = self.decoders();

        // TODO: only include some of the proposals for realism
        let mut consensus = vec![];
        for (id, member, db) in &mut self.members {
            consensus.extend(
                member
                    .consensus_proposal(&mut db.begin_transaction(decoders.clone()))
                    .await
                    .into_iter()
                    .map(|ci| (*id, ci)),
            );
        }

        let peers: HashSet<PeerId> = self.members.iter().map(|p| p.0).collect();
        let decoders = self.decoders();
        for (_peer, member, db) in &mut self.members {
            let database = db as &mut Database;
            let mut dbtx = database.begin_transaction(decoders.clone());

            member
                .begin_consensus_epoch(&mut dbtx, consensus.clone())
                .await;

            let cache = member.build_verification_cache(inputs.iter());
            for input in inputs {
                member
                    .apply_input(&fake_ic, &mut dbtx, input, &cache)
                    .await
                    .expect("Faulty input");
            }

            for (out_point, output) in outputs {
                member
                    .apply_output(&mut dbtx, output, *out_point)
                    .await
                    .expect("Faulty output");
            }

            dbtx.commit_tx().await.expect("DB Error");

            let mut dbtx = database.begin_transaction(decoders.clone());
            member.end_consensus_epoch(&peers, &mut dbtx).await;

            dbtx.commit_tx().await.expect("DB Error");
        }
    }

    pub async fn output_outcome(&self, out_point: OutPoint) -> Option<Module::OutputOutcome> {
        // Since every member is in the same epoch they should have the same internal state, even
        // in terms of outcomes. This may change later once end_consensus_epoch is pulled out of the
        // main consensus loop into another thread to optimize latency. This test will probably fail
        // then.
        let mut results = Vec::new();
        for (_, member, db) in self.members.iter() {
            results.push(
                member
                    .output_status(&mut db.begin_transaction(self.decoders()), out_point)
                    .await,
            );
        }
        assert_all_equal(results.into_iter())
    }

    pub async fn patch_dbs<U>(&mut self, update: U)
    where
        U: Fn(&mut DatabaseTransaction),
    {
        let decoders = self.decoders();
        for (_, _, db) in &mut self.members {
            let mut dbtx = db.begin_transaction(decoders.clone());
            update(&mut dbtx);
            dbtx.commit_tx().await.expect("DB Error");
        }
    }

    pub async fn generate_fake_utxo(&mut self) {
        let decoders = self.decoders();
        for (_, _, db) in &mut self.members {
            let mut dbtx = db.begin_transaction(decoders.clone());
            let out_point = bitcoin::OutPoint::default();
            let tweak = [42; 32];
            let utxo = fedimint_wallet::SpendableUTXO {
                tweak,
                amount: bitcoin::Amount::from_sat(48000),
            };

            dbtx.insert_entry(&fedimint_wallet::db::UTXOKey(out_point), &utxo)
                .await
                .unwrap();

            dbtx.insert_entry(
                &fedimint_wallet::db::RoundConsensusKey,
                &fedimint_wallet::RoundConsensus {
                    block_height: 0,
                    fee_rate: fedimint_api::Feerate { sats_per_kvb: 0 },
                    randomness_beacon: tweak,
                },
            )
            .await
            .unwrap();
            dbtx.commit_tx().await.expect("DB Error");
        }
    }

    pub fn client_cfg(&self) -> &ClientModuleConfig {
        &self.client_cfg
    }

    pub fn client_cfg_typed<T: serde::de::DeserializeOwned>(&self) -> anyhow::Result<T> {
        Ok(serde_json::from_value(self.client_cfg.0.clone())?)
    }

    pub async fn fetch_from_all<'a: 'b, 'b, O, F, Fut>(&'a mut self, fetch: F) -> O
    where
        O: Debug + Eq + Send,
        F: Fn(&'b mut Module, &'b mut Database) -> Fut,
        Fut: futures::Future<Output = O> + Send,
    {
        let mut results = Vec::new();
        for (_, member, db) in self.members.iter_mut() {
            results.push(fetch(member, db).await);
        }
        assert_all_equal(results.into_iter())
    }
}

fn assert_all_equal<I>(mut iter: I) -> I::Item
where
    I: Iterator,
    I::Item: Eq + Debug,
{
    let first = iter.next().expect("empty iterator");
    for item in iter {
        assert_eq!(first, item);
    }
    first
}

/// Make sure all elements are equal for `Result<O, E>`
///
/// For errors their conversion to `String` via `Debug` is used to avoid
/// `E : Eq`.
fn assert_all_equal_result<I, O, E>(mut iter: I) -> I::Item
where
    I: Iterator<Item = Result<O, E>>,
    O: Eq + Debug,
    E: Debug,
{
    let first = iter.next().expect("empty iterator");

    match &first {
        Ok(first) => {
            for item in iter {
                match item {
                    Ok(item) => {
                        assert_eq!(first, &item);
                    }
                    Err(e) => {
                        panic!("Assertion error: Ok({first:?}) != Err({e:?})");
                    }
                }
            }
        }
        Err(first) => {
            let first = format!("{first:?}");

            for item in iter {
                match item {
                    Ok(o) => {
                        panic!("Assertion error: Err({first}) != Ok({o:?})");
                    }
                    Err(e) => {
                        assert_eq!(first, format!("{e:?}"));
                    }
                }
            }
        }
    }

    first
}

struct FakeInterconnect(
    Box<
        dyn Fn(&'static str, String, serde_json::Value) -> Result<serde_json::Value, ApiError>
            + Sync
            + Send,
    >,
);

impl FakeInterconnect {
    fn new_block_height_responder(bh: Arc<AtomicU64>) -> FakeInterconnect {
        FakeInterconnect(Box::new(move |module, path, _data| {
            assert_eq!(module, "wallet");
            assert_eq!(path, "/block_height");

            let height = bh.load(Ordering::Relaxed);
            Ok(serde_json::to_value(height).expect("encoding error"))
        }))
    }
}

#[async_trait]
impl ModuleInterconect for FakeInterconnect {
    async fn call(
        &self,
        module: &'static str,
        path: String,
        data: serde_json::Value,
    ) -> Result<serde_json::Value, ApiError> {
        (self.0)(module, path, data)
    }
}
