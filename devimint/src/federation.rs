mod config;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::time::Duration;
use std::{env, fs};

use anyhow::{anyhow, bail, Context, Result};
use bitcoincore_rpc::bitcoin::Network;
use fedimint_core::admin_client::{ConfigGenConnectionsRequest, ConfigGenParamsRequest};
use fedimint_core::api::{DynGlobalApi, ServerStatus};
use fedimint_core::config::{load_from_file, ClientConfig, ServerModuleConfigGenParamsRegistry};
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_WALLET;
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ApiAuth, ModuleCommon};
use fedimint_core::util::SafeUrl;
use fedimint_core::PeerId;
use fedimint_logging::LOG_DEVIMINT;
use fedimint_server::config::ConfigGenParams;
use fedimint_testing::federation::local_config_gen_params;
use fedimint_wallet_client::config::WalletClientConfig;
use fedimintd::FM_EXTRA_DKG_META_VAR;
use fs_lock::FileLock;
use futures::future::join_all;
use rand::Rng;
use semver::VersionReq;
use tokio::time::Instant;
use tracing::{debug, info};

use super::external::Bitcoind;
use super::util::{cmd, parse_map, Command, ProcessHandle, ProcessManager};
use super::vars::utf8;
use crate::util::{poll, FedimintdCmd};
use crate::{poll_eq, vars};

#[derive(Clone)]
pub struct Federation {
    // client is only for internal use, use cli commands instead
    pub members: BTreeMap<usize, Fedimintd>,
    pub vars: BTreeMap<usize, vars::Fedimintd>,
    pub bitcoind: Bitcoind,

    /// Built in [`Client`]
    client: Client,
}

/// `fedimint-cli` instance (basically path with client state: config + db)
#[derive(Clone)]
pub struct Client {
    name: String,
}

impl Client {
    fn clients_dir() -> PathBuf {
        let data_dir: PathBuf = env::var("FM_DATA_DIR")
            .expect("FM_DATA_DIR not set")
            .parse()
            .expect("FM_DATA_DIR invalid");
        data_dir.join("clients")
    }

    fn client_dir(&self) -> PathBuf {
        Self::clients_dir().join(&self.name)
    }

    pub fn client_name_lock(name: &str) -> Result<FileLock> {
        let lock_path = Self::clients_dir().join(format!(".{name}.lock"));
        let file_lock = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&lock_path)
            .with_context(|| format!("Failed to open {}", lock_path.display()))?;

        fs_lock::FileLock::new_exclusive(file_lock)
            .with_context(|| format!("Failed to lock {}", lock_path.display()))
    }

    /// Create a [`Client`] that starts with a fresh state.
    pub async fn create(name: &str) -> Result<Client> {
        tokio::task::block_in_place(|| {
            let _lock = Self::client_name_lock(name);
            for i in 0u64.. {
                let client = Self {
                    name: format!("{name}-{i}"),
                };

                if !client.client_dir().exists() {
                    std::fs::create_dir_all(client.client_dir())?;
                    return Ok(client);
                }
            }
            unreachable!()
        })
    }

    /// Open or create a [`Client`] that starts with a fresh state.
    pub async fn open_or_create(name: &str) -> Result<Client> {
        tokio::task::block_in_place(|| {
            let _lock = Self::client_name_lock(name);
            let client = Self {
                name: format!("{name}-0"),
            };
            if !client.client_dir().exists() {
                std::fs::create_dir_all(client.client_dir())?;
            }
            Ok(client)
        })
    }

    /// Client to join a federation
    pub async fn join_federation(&self, invite_code: String) -> Result<()> {
        debug!(target: LOG_DEVIMINT, "Joining federation with the main client");
        cmd!(self, "join-federation", invite_code).run().await?;

        Ok(())
    }

    /// Create a [`Client`] that starts with a state that is a copy of
    /// of another one.
    pub async fn new_forked(&self, name: &str) -> Result<Client> {
        let new = Client::create(name).await?;

        cmd!(
            "cp",
            "-R",
            self.client_dir().join("client.db").display(),
            new.client_dir().display()
        )
        .run()
        .await?;

        Ok(new)
    }

    pub async fn balance(&self) -> Result<u64> {
        Ok(cmd!(self, "info").out_json().await?["total_amount_msat"]
            .as_u64()
            .unwrap())
    }

    // TODO(support:v0.2): remove
    pub async fn use_gateway(&self, gw: &super::gatewayd::Gatewayd) -> Result<()> {
        let fedimint_cli_version = crate::util::FedimintCli::version_or_default().await;
        if VersionReq::parse("<0.3.0-alpha")?.matches(&fedimint_cli_version) {
            let gateway_id = gw.gateway_id().await?;
            cmd!(self, "switch-gateway", gateway_id.clone())
                .run()
                .await?;
            info!(
                "Using {name} gateway",
                name = gw.ln.as_ref().unwrap().name()
            );
        }

        Ok(())
    }

    pub async fn get_deposit_addr(&self) -> Result<(String, String)> {
        let deposit = cmd!(self, "deposit-address").out_json().await?;
        Ok((
            deposit["address"].as_str().unwrap().to_string(),
            deposit["operation_id"].as_str().unwrap().to_string(),
        ))
    }

    pub async fn await_deposit(&self, operation_id: &str) -> Result<()> {
        cmd!(self, "await-deposit", operation_id).run().await
    }

    pub async fn cmd(&self) -> Command {
        cmd!(
            crate::util::get_fedimint_cli_path(),
            format!("--data-dir={}", self.client_dir().display())
        )
    }
}

impl Federation {
    pub async fn new(
        process_mgr: &ProcessManager,
        bitcoind: Bitcoind,
        servers: usize,
    ) -> Result<Self> {
        let mut members = BTreeMap::new();
        let mut peer_to_env_vars_map = BTreeMap::new();

        let peers: Vec<_> = (0..servers).map(|id| PeerId::from(id as u16)).collect();
        let params: HashMap<PeerId, ConfigGenParams> = local_config_gen_params(
            &peers,
            process_mgr.globals.FM_PORT_FEDIMINTD_BASE,
            ServerModuleConfigGenParamsRegistry::default(),
        )?;

        let mut admin_clients: BTreeMap<PeerId, DynGlobalApi> = BTreeMap::new();
        for (peer, peer_params) in &params {
            let peer_env_vars =
                vars::Fedimintd::init(&process_mgr.globals, peer_params.to_owned()).await?;
            members.insert(
                peer.to_usize(),
                Fedimintd::new(
                    process_mgr,
                    bitcoind.clone(),
                    peer.to_usize(),
                    &peer_env_vars,
                )
                .await?,
            );
            let admin_client =
                DynGlobalApi::from_pre_peer_id_endpoint(SafeUrl::parse(&peer_env_vars.FM_API_URL)?);
            admin_clients.insert(*peer, admin_client);
            peer_to_env_vars_map.insert(peer.to_usize(), peer_env_vars);
        }

        run_dkg(admin_clients, params).await?;

        // move configs to config directory
        let client_dir = utf8(&process_mgr.globals.FM_CLIENT_DIR);
        let invite_code_filename_original = "invite-code";

        // copy over invite-code file to client directory
        let peer_data_dir = utf8(&peer_to_env_vars_map[&0].FM_DATA_DIR);
        tokio::fs::copy(
            format!("{peer_data_dir}/{invite_code_filename_original}"),
            format!("{client_dir}/{invite_code_filename_original}"),
        )
        .await
        .context("copying invite-code file")?;

        // move each guardian's invite-code file to the client's directory
        // appending the peer id to the end
        for (index, peer_env_vars) in &peer_to_env_vars_map {
            let peer_data_dir = utf8(&peer_env_vars.FM_DATA_DIR);

            let invite_code_filename_indexed = format!("{invite_code_filename_original}-{}", index);
            tokio::fs::rename(
                format!("{peer_data_dir}/{}", invite_code_filename_original),
                format!("{client_dir}/{}", invite_code_filename_indexed),
            )
            .await
            .context("moving invite-code file")?;
        }
        debug!("Moved invite-code files to client data directory");

        Ok(Self {
            members,
            vars: peer_to_env_vars_map,
            bitcoind,
            client: Client::open_or_create("default").await?,
        })
    }

    pub async fn client_config(&self) -> Result<ClientConfig> {
        let cfg_path = self.vars[&0].FM_DATA_DIR.join("client.json");
        load_from_file(&cfg_path)
    }

    /// Read the invite code from the client data dir
    pub fn invite_code(&self) -> Result<String> {
        let data_dir: PathBuf = env::var("FM_CLIENT_DIR")?.parse()?;
        let invite_code = fs::read_to_string(data_dir.join("invite-code"))?;
        Ok(invite_code)
    }

    pub fn invite_code_for(peer_id: PeerId) -> Result<String> {
        let data_dir: PathBuf = env::var("FM_CLIENT_DIR")?.parse()?;
        let name = format!("invite-code-{}", peer_id);
        let invite_code = fs::read_to_string(data_dir.join(name))?;
        Ok(invite_code)
    }

    /// Built-in, default, internal [`Client`]
    ///
    /// We should be moving away from using it for anything.
    pub fn internal_client(&self) -> &Client {
        &self.client
    }

    /// Fork the built-in client of `Federation` and give it a name
    pub async fn fork_client(&self, name: &str) -> Result<Client> {
        Client::new_forked(&self.client, name).await
    }

    /// New [`Client`] that already joined `self`
    pub async fn new_joined_client(&self, name: &str) -> Result<Client> {
        let client = Client::create(name).await?;
        client.join_federation(self.invite_code()?).await?;
        Ok(client)
    }

    pub async fn start_server(&mut self, process_mgr: &ProcessManager, peer: usize) -> Result<()> {
        if self.members.contains_key(&peer) {
            bail!("fedimintd-{peer} already running");
        }
        self.members.insert(
            peer,
            Fedimintd::new(process_mgr, self.bitcoind.clone(), peer, &self.vars[&peer]).await?,
        );
        Ok(())
    }

    pub async fn terminate_server(&mut self, peer_id: usize) -> Result<()> {
        let Some((_, fedimintd)) = self.members.remove_entry(&peer_id) else {
            bail!("fedimintd-{peer_id} does not exist");
        };
        fedimintd.terminate().await?;
        Ok(())
    }

    pub async fn degrade_federation(&mut self, process_mgr: &ProcessManager) -> Result<()> {
        let fed_size = process_mgr.globals.FM_FED_SIZE;
        let offline_nodes = process_mgr.globals.FM_OFFLINE_NODES;
        anyhow::ensure!(
            fed_size > 3 * offline_nodes,
            "too many offline nodes ({offline_nodes}) to reach consensus"
        );

        while self.num_members() > fed_size - offline_nodes {
            self.terminate_server(self.num_members() - 1).await?;
        }

        if offline_nodes > 0 {
            info!(fed_size, offline_nodes, "federation is degraded");
        }
        Ok(())
    }

    pub async fn pegin_client(&self, amount: u64, client: &Client) -> Result<()> {
        info!(amount, "Pegging-in client funds");

        let (address, operation_id) = client.get_deposit_addr().await?;

        self.bitcoind.send_to(address, amount).await?;
        self.bitcoind.mine_blocks(21).await?;

        client.await_deposit(&operation_id).await?;
        Ok(())
    }

    pub async fn pegin_gateway(&self, amount: u64, gw: &super::gatewayd::Gatewayd) -> Result<()> {
        info!(amount, "Pegging-in gateway funds");
        let fed_id = self.calculate_federation_id().await;
        let pegin_addr = gw.get_pegin_addr(&fed_id).await?;
        self.bitcoind.send_to(pegin_addr, amount).await?;
        self.bitcoind.mine_blocks(21).await?;
        poll("gateway pegin", None, || async {
            let gateway_balance = cmd!(gw, "balance", "--federation-id={fed_id}")
                .out_json()
                .await
                .map_err(ControlFlow::Continue)?
                .as_u64()
                .unwrap();
            poll_eq!(gateway_balance, amount * 1000)
        })
        .await?;
        Ok(())
    }

    pub async fn calculate_federation_id(&self) -> String {
        self.client_config()
            .await
            .unwrap()
            .global
            .calculate_federation_id()
            .to_string()
    }

    pub async fn await_block_sync(&self) -> Result<u64> {
        let finality_delay = self.get_finality_delay().await?;
        let block_count = self.bitcoind.get_block_count()?;
        let expected = block_count.saturating_sub(finality_delay.into());
        cmd!(self.client, "dev", "wait-block-count", expected)
            .run()
            .await?;
        Ok(expected)
    }

    async fn get_finality_delay(&self) -> Result<u32, anyhow::Error> {
        let client_config = &self.client_config().await?;
        let wallet_cfg = client_config
            .modules
            .get(&LEGACY_HARDCODED_INSTANCE_ID_WALLET)
            .context("wallet module not found")?
            .clone()
            .redecode_raw(&ModuleDecoderRegistry::new([(
                LEGACY_HARDCODED_INSTANCE_ID_WALLET,
                fedimint_wallet_client::KIND,
                fedimint_wallet_client::WalletModuleTypes::decoder(),
            )]))?;
        let wallet_cfg: &WalletClientConfig = wallet_cfg.cast()?;

        let finality_delay = wallet_cfg.finality_delay;
        Ok(finality_delay)
    }

    pub async fn await_gateways_registered(&self) -> Result<()> {
        let start_time = Instant::now();
        debug!(target: LOG_DEVIMINT, "Awaiting LN gateways registration");
        let fedimint_cli_version = crate::util::FedimintCli::version_or_default().await;
        let command = if VersionReq::parse("<0.3.0-alpha")?.matches(&fedimint_cli_version) {
            "list-gateways"
        } else {
            "update-gateway-cache"
        };

        poll("gateways registered", None, || async {
            let num_gateways = cmd!(self.client, command)
                .out_json()
                .await
                .map_err(ControlFlow::Continue)?
                .as_array()
                .context("invalid output")
                .map_err(ControlFlow::Break)?
                .len();
            poll_eq!(num_gateways, 2)
        })
        .await?;
        debug!(target: LOG_DEVIMINT,
            elapsed_ms = %start_time.elapsed().as_millis(),
            "Gateways registered");
        Ok(())
    }

    pub async fn await_all_peers(&self) -> Result<()> {
        poll("Waiting for all peers to be online", None, || async {
            cmd!(
                self.client,
                "dev",
                "api",
                "module_{LEGACY_HARDCODED_INSTANCE_ID_WALLET}_block_count"
            )
            .run()
            .await
            .map_err(ControlFlow::Continue)?;
            Ok(())
        })
        .await
    }

    /// Mines enough blocks to finalize mempool transactions, then waits for
    /// federation to process finalized blocks.
    ///
    /// ex:
    ///   tx submitted to mempool at height 100
    ///   finality delay = 10
    ///   mine finality delay blocks + 1 => new height 111
    ///   tx included in block 101
    ///   highest finalized height = 111 - 10 = 101
    pub async fn finalize_mempool_tx(&self) -> Result<()> {
        let finality_delay = self.get_finality_delay().await?;
        let blocks_to_mine = finality_delay + 1;
        self.bitcoind.mine_blocks(blocks_to_mine.into()).await?;
        self.await_block_sync().await?;
        Ok(())
    }

    pub async fn mine_then_wait_blocks_sync(&self, blocks: u64) -> Result<()> {
        self.bitcoind.mine_blocks(blocks).await?;
        self.await_block_sync().await?;
        Ok(())
    }

    pub fn num_members(&self) -> usize {
        self.members.len()
    }
}

#[derive(Clone)]
pub struct Fedimintd {
    _bitcoind: Bitcoind,
    process: ProcessHandle,
}

impl Fedimintd {
    pub async fn new(
        process_mgr: &ProcessManager,
        bitcoind: Bitcoind,
        peer_id: usize,
        env: &vars::Fedimintd,
    ) -> Result<Self> {
        debug!("Starting fedimintd-{peer_id}");
        let process = process_mgr
            .spawn_daemon(
                &format!("fedimintd-{peer_id}"),
                cmd!(FedimintdCmd).envs(env.vars()),
            )
            .await?;

        Ok(Self {
            _bitcoind: bitcoind,
            process,
        })
    }

    pub async fn terminate(self) -> Result<()> {
        self.process.terminate().await
    }
}

pub async fn run_dkg(
    admin_clients: BTreeMap<PeerId, DynGlobalApi>,
    params: HashMap<PeerId, ConfigGenParams>,
) -> Result<()> {
    let auth_for = |peer: &PeerId| -> ApiAuth { params[peer].local.api_auth.clone() };
    for (peer_id, client) in &admin_clients {
        poll(
            "trying-to-connect-to-peers",
            Duration::from_secs(30),
            || async {
                client
                    .status()
                    .await
                    .context("dkg status")
                    .map_err(ControlFlow::Continue)
            },
        )
        .await?;
        debug!("Connected to {peer_id}")
    }
    for (peer_id, client) in &admin_clients {
        assert_eq!(
            client.status().await?.server,
            fedimint_core::api::ServerStatus::AwaitingPassword,
            "peer_id isn't waiting for password: {peer_id}"
        );
    }

    for (peer_id, client) in &admin_clients {
        client.set_password(auth_for(peer_id)).await?;
    }
    let (leader_id, leader) = admin_clients.iter().next().context("missing peer")?;
    let followers = admin_clients
        .iter()
        .filter(|(id, _)| *id != leader_id)
        .collect::<BTreeMap<_, _>>();

    let leader_name = "leader".to_string();
    leader
        .set_config_gen_connections(
            ConfigGenConnectionsRequest {
                our_name: leader_name.clone(),
                leader_api_url: None,
            },
            auth_for(leader_id),
        )
        .await?;

    let _ = leader
        .get_default_config_gen_params(auth_for(leader_id))
        .await?; // sanity check
    let server_gen_params = params[leader_id].consensus.modules.clone();
    set_config_gen_params(leader, auth_for(leader_id), server_gen_params.clone()).await?;
    let followers_names = followers
        .keys()
        .map(|peer_id| {
            (*peer_id, {
                // This is to be clear that the name will be unrelated to peer id
                let random_string = rand::thread_rng()
                    .sample_iter(&rand::distributions::Alphanumeric)
                    .take(5)
                    .map(char::from)
                    .collect::<String>();
                format!("random-{random_string}{peer_id}")
            })
        })
        .collect::<BTreeMap<_, _>>();
    for (peer_id, client) in &followers {
        let name = followers_names
            .get(peer_id)
            .context("missing follower name")?;
        debug!("calling set_config_gen_connections for {peer_id} {name}");
        client
            .set_config_gen_connections(
                ConfigGenConnectionsRequest {
                    our_name: name.clone(),
                    leader_api_url: Some(
                        params
                            .get(leader_id)
                            .expect("Must have leader configs")
                            .consensus
                            .peers
                            .get(leader_id)
                            .expect("Must have leader api_endpoint")
                            .api_url
                            .clone(),
                    ),
                },
                auth_for(peer_id),
            )
            .await?;
        set_config_gen_params(client, auth_for(peer_id), server_gen_params.clone()).await?;
    }
    let found_names = leader
        .get_config_gen_peers()
        .await?
        .into_iter()
        .map(|peer| peer.name)
        .collect::<HashSet<_>>();
    let all_names = {
        let mut names = followers_names.values().cloned().collect::<HashSet<_>>();
        names.insert(leader_name);
        names
    };
    assert_eq!(found_names, all_names);
    wait_server_status(leader, ServerStatus::SharingConfigGenParams).await?;

    let mut configs = vec![];
    for client in admin_clients.values() {
        configs.push(client.consensus_config_gen_params().await?);
    }
    // Confirm all consensus configs are the same
    let mut consensus: Vec<_> = configs.iter().map(|p| p.consensus.clone()).collect();
    consensus.dedup();
    assert_eq!(consensus.len(), 1);
    // Confirm all peer ids are unique
    let ids = configs
        .iter()
        .map(|p| p.our_current_id)
        .collect::<HashSet<_>>();
    assert_eq!(ids.len(), admin_clients.len());
    let dkg_results = admin_clients
        .iter()
        .map(|(peer_id, client)| client.run_dkg(auth_for(peer_id)));
    info!(target: LOG_DEVIMINT, "Running DKG");
    let (dkg_results, leader_wait_result) = tokio::join!(
        join_all(dkg_results),
        wait_server_status(leader, ServerStatus::VerifyingConfigs)
    );
    for result in dkg_results {
        result?;
    }
    leader_wait_result?;

    // verify config hashes equal for all peers
    let mut hashes = HashSet::new();
    for (peer_id, client) in &admin_clients {
        wait_server_status(client, ServerStatus::VerifyingConfigs).await?;
        hashes.insert(client.get_verify_config_hash(auth_for(peer_id)).await?);
    }
    assert_eq!(hashes.len(), 1);
    debug!(target: LOG_DEVIMINT, "DKG ready");
    info!(target: LOG_DEVIMINT, "Starting consensus");
    for (peer_id, client) in &admin_clients {
        if let Err(e) = client.start_consensus(auth_for(peer_id)).await {
            tracing::debug!("Error calling start_consensus: {e:?}, trying to continue...")
        }
        wait_server_status(client, ServerStatus::ConsensusRunning).await?;
    }
    debug!("Consensus is running");
    Ok(())
}

async fn set_config_gen_params(
    client: &DynGlobalApi,
    auth: ApiAuth,
    mut server_gen_params: ServerModuleConfigGenParamsRegistry,
) -> Result<()> {
    self::config::attach_default_module_init_params(
        BitcoinRpcConfig::from_env_vars()?,
        &mut server_gen_params,
        Network::Regtest,
        10,
    );
    // Since we are not actually calling `fedimintd` binary, parse and handle
    // `FM_EXTRA_META_DATA` like it would do.
    let mut extra_meta_data = parse_map(
        &std::env::var(FM_EXTRA_DKG_META_VAR)
            .ok()
            .unwrap_or_default(),
    )
    .with_context(|| format!("Failed to parse {FM_EXTRA_DKG_META_VAR}"))
    .expect("Failed");
    let mut meta = BTreeMap::from([("federation_name".to_string(), "testfed".to_string())]);
    meta.append(&mut extra_meta_data);

    let request = ConfigGenParamsRequest {
        meta,
        modules: server_gen_params,
    };
    client.set_config_gen_params(request, auth.clone()).await?;
    Ok(())
}

async fn wait_server_status(client: &DynGlobalApi, expected_status: ServerStatus) -> Result<()> {
    poll(
        &format!("waiting-server-status: {expected_status:?}"),
        Duration::from_secs(60),
        || async {
            let server_status = client
                .status()
                .await
                .context("server status")
                .map_err(ControlFlow::Continue)?
                .server;
            if server_status == expected_status {
                Ok(())
            } else {
                Err(ControlFlow::Continue(anyhow!(
                    "expected status: {expected_status:?} current status: {server_status:?}"
                )))
            }
        },
    )
    .await?;
    Ok(())
}
