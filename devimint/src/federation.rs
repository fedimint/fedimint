use std::collections::{BTreeMap, HashSet};
use std::fs;

use anyhow::{bail, Context};
use bitcoincore_rpc::bitcoin::Network;
use fedimint_core::admin_client::{ConfigGenConnectionsRequest, ConfigGenParamsRequest};
use fedimint_core::api::ServerStatus;
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::config::ServerModuleGenParamsRegistry;
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_WALLET;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::ApiAuth;
use fedimint_core::{Amount, PeerId};
use fedimint_server::config::ConfigGenParams;
use fedimint_testing::federation::local_config_gen_params;
use fedimint_wallet_client::config::WalletClientConfig;
use fedimintd::attach_default_module_gen_params;
use futures::future::join_all;
use rand::Rng;
use url::Url;

use super::*; // TODO: remove this

pub struct Federation {
    // client is only for internal use, use cli commands instead
    members: BTreeMap<usize, Fedimintd>,
    vars: BTreeMap<usize, vars::Fedimintd>,
    bitcoind: Bitcoind,
}

/// `fedimint-cli` instance (basically path with client state: config + db)
pub struct Client {
    path: PathBuf,
}

impl Client {
    /// Create a [`Client`] that starts with a state that is a copy of
    /// of a [`Federation`] built-in client's state.
    ///
    /// TODO: Get rid of built-in client, make it a normal `Client` and let them
    /// fork each other as they please.
    async fn new_forked(name: &str) -> Result<Client> {
        let workdir: PathBuf = env::var("FM_DATA_DIR")?.parse()?;
        let client_dir = workdir.join("clients").join(name);

        std::fs::create_dir_all(&client_dir)?;

        cmd!(
            "cp",
            "-R",
            workdir.join("client.json").display(),
            client_dir.join("client.json").display()
        )
        .run()
        .await?;

        cmd!(
            "cp",
            "-R",
            workdir.join("client.db").display(),
            client_dir.join("client.db").display()
        )
        .run()
        .await?;

        Ok(Self { path: client_dir })
    }

    pub async fn cmd(&self) -> Command {
        cmd!(
            "fedimint-cli",
            format!("--data-dir={}", self.path.display())
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
        let mut vars = BTreeMap::new();

        let peers: Vec<_> = (0..servers).map(|id| PeerId::from(id as u16)).collect();
        let params: HashMap<PeerId, ConfigGenParams> =
            local_config_gen_params(&peers, BASE_PORT, ServerModuleGenParamsRegistry::default())?;

        let mut admin_clients: BTreeMap<PeerId, WsAdminClient> = BTreeMap::new();
        for (peer, peer_params) in &params {
            let var = vars::Fedimintd::init(&process_mgr.globals, peer_params.to_owned()).await?;
            members.insert(
                peer.to_usize(),
                Fedimintd::new(process_mgr, bitcoind.clone(), peer.to_usize(), &var).await?,
            );
            let admin_client = WsAdminClient::new(Url::parse(&var.FM_API_URL)?);
            admin_clients.insert(*peer, admin_client);
            vars.insert(peer.to_usize(), var);
        }

        run_dkg(admin_clients, params).await?;

        let out_dir = &vars[&0].FM_DATA_DIR;
        let cfg_dir = &process_mgr.globals.FM_DATA_DIR;
        let out_dir = utf8(out_dir);
        let cfg_dir = utf8(cfg_dir);
        // copy configs to config directory
        tokio::fs::rename(
            format!("{out_dir}/invite-code"),
            format!("{cfg_dir}/invite-code"),
        )
        .await?;
        tokio::fs::rename(
            format!("{out_dir}/client.json"),
            format!("{cfg_dir}/client.json"),
        )
        .await?;
        info!("copied client configs");

        Ok(Self {
            members,
            vars,
            bitcoind,
        })
    }

    pub async fn client(&self) -> Result<UserClient> {
        let workdir: PathBuf = env::var("FM_DATA_DIR")?.parse()?;
        let cfg_path = workdir.join("client.json");
        let mut cfg: UserClientConfig = load_from_file(&cfg_path)?;
        let decoders = module_decode_stubs();
        cfg.0 = cfg.0.redecode_raw(&decoders)?;
        let db = Database::new(MemDatabase::new(), module_decode_stubs());
        let module_gens = ClientModuleGenRegistry::from(vec![
            DynClientModuleGen::from(WalletClientGen::default()),
            DynClientModuleGen::from(MintClientGen),
            DynClientModuleGen::from(LightningClientGen),
        ]);
        let client = UserClient::new(cfg, decoders, module_gens, db, Default::default()).await;
        Ok(client)
    }

    pub fn invite_code(&self) -> Result<String> {
        let workdir: PathBuf = env::var("FM_DATA_DIR")?.parse()?;
        let invite_code = fs::read_to_string(workdir.join("invite-code"))?;
        Ok(invite_code)
    }

    /// Fork the built-in client of `Federation` and give it a name
    pub async fn fork_client(&self, name: &str) -> Result<Client> {
        Client::new_forked(name).await
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

    pub async fn cmd(&self) -> Command {
        let cfg_dir = env::var("FM_DATA_DIR").unwrap();
        cmd!("fedimint-cli", "--data-dir={cfg_dir}")
    }

    pub async fn pegin(&self, amount: u64) -> Result<()> {
        info!(amount, "Peg-in");
        let deposit = cmd!(self, "deposit-address").out_json().await?;
        let deposit_address = deposit["address"].as_str().unwrap();
        let deposit_operation_id = deposit["operation_id"].as_str().unwrap();

        self.bitcoind
            .send_to(deposit_address.to_owned(), amount)
            .await?;
        self.bitcoind.mine_blocks(100).await?;

        cmd!(self, "await-deposit", deposit_operation_id)
            .run()
            .await?;
        Ok(())
    }

    pub async fn pegin_gateway(&self, amount: u64, gw: &Gatewayd) -> Result<()> {
        info!(amount, "Pegging-in gateway funds");
        let fed_id = self.federation_id().await;
        let pegin_addr = cmd!(gw, "address", "--federation-id={fed_id}")
            .out_json()
            .await?
            .as_str()
            .context("address must be a string")?
            .to_owned();
        self.bitcoind.send_to(pegin_addr, amount).await?;
        self.bitcoind.mine_blocks(21).await?;
        poll("gateway pegin", || async {
            let gateway_balance = cmd!(gw, "balance", "--federation-id={fed_id}")
                .out_json()
                .await?
                .as_u64()
                .unwrap();

            Ok(gateway_balance == (amount * 1000))
        })
        .await?;
        Ok(())
    }

    pub async fn federation_id(&self) -> String {
        self.client()
            .await
            .unwrap()
            .config()
            .0
            .federation_id
            .to_string()
    }

    pub async fn await_block_sync(&self) -> Result<()> {
        let client = self.client().await?;
        let wallet_cfg: &WalletClientConfig = client
            .config_ref()
            .0
            .get_module(LEGACY_HARDCODED_INSTANCE_ID_WALLET)?;
        let finality_delay = wallet_cfg.finality_delay;
        let bitcoind_block_count = self.bitcoind.client().get_blockchain_info()?.blocks;
        let expected = bitcoind_block_count - (finality_delay as u64);
        cmd!(self, "dev", "wait-block-count", expected)
            .run()
            .await?;
        Ok(())
    }

    pub async fn await_gateways_registered(&self) -> Result<()> {
        poll("gateways registered", || async {
            Ok(cmd!(self, "list-gateways")
                .out_json()
                .await?
                .as_array()
                .map_or(false, |x| x.len() == 2))
        })
        .await?;
        Ok(())
    }

    pub async fn await_all_peers(&self) -> Result<()> {
        cmd!(
            self,
            "dev",
            "api",
            "module_{LEGACY_HARDCODED_INSTANCE_ID_WALLET}_block_count"
        )
        .run()
        .await?;
        Ok(())
    }

    pub async fn use_gateway(&self, gw: &Gatewayd) -> Result<()> {
        let gateway_id = gw.gateway_id().await?;
        cmd!(self, "switch-gateway", gateway_id.clone())
            .run()
            .await?;
        info!(
            "Using {name} gateway",
            name = gw.ln.as_ref().unwrap().name()
        );
        Ok(())
    }

    pub async fn generate_epochs(&self, epochs: usize) -> Result<()> {
        for _ in 0..epochs {
            self.bitcoind.mine_blocks(10).await?;
            self.await_block_sync().await?;
        }
        Ok(())
    }

    pub async fn client_balance(&self) -> Result<u64> {
        Ok(cmd!(self, "info").out_json().await?["total_msat"]
            .as_u64()
            .unwrap())
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
        info!("fedimintd-{peer_id} started");
        let process = process_mgr
            .spawn_daemon(
                &format!("fedimintd-{peer_id}"),
                cmd!("fedimintd").envs(env.vars()),
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

/// Base port for devimint
const BASE_PORT: u16 = 8173 + 10000;

pub async fn run_dkg(
    admin_clients: BTreeMap<PeerId, WsAdminClient>,
    params: HashMap<PeerId, ConfigGenParams>,
) -> anyhow::Result<()> {
    let auth_for = |peer: &PeerId| -> ApiAuth { params[peer].local.api_auth.clone() };
    for (peer_id, client) in &admin_clients {
        const MAX_RETRIES: usize = 20;
        poll_max_retries("trying-to-connect-to-peers", MAX_RETRIES, || async {
            Ok(client.status().await.is_ok())
        })
        .await?;
        info!("Connected to {peer_id}")
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
        info!("calling set_config_gen_connections for {peer_id} {name}");
        client
            .set_config_gen_connections(
                ConfigGenConnectionsRequest {
                    our_name: name.clone(),
                    leader_api_url: Some(leader.url.clone()),
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
        configs.push(client.get_consensus_config_gen_params().await?);
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
    info!("Running DKG...");
    let (dkg_results, leader_wait_result) = tokio::join!(
        join_all(dkg_results),
        wait_server_status(leader, ServerStatus::ReadyForConfigGen)
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
    info!("DKG successfully complete. Starting consensus...");
    for (peer_id, client) in &admin_clients {
        if let Err(e) = client.start_consensus(auth_for(peer_id)).await {
            tracing::info!("Error calling start_consensus: {e:?}, trying to continue...")
        }
        const RETRIES: usize = 20;
        poll_max_retries("waiting-consensus-running-for-peer", RETRIES, || async {
            Ok(client.status().await?.server == ServerStatus::ConsensusRunning)
        })
        .await?;
    }
    info!("Consensus is running");
    Ok(())
}

async fn set_config_gen_params(
    client: &WsAdminClient,
    auth: ApiAuth,
    mut server_gen_params: ServerModuleGenParamsRegistry,
) -> anyhow::Result<()> {
    attach_default_module_gen_params(
        BitcoinRpcConfig::from_env_vars()?,
        &mut server_gen_params,
        Amount::from_sats(100_000_000),
        Network::Regtest,
        10,
    );
    let request = ConfigGenParamsRequest {
        meta: BTreeMap::from([("federation_name".to_string(), "testfed".to_string())]),
        modules: server_gen_params,
    };
    client.set_config_gen_params(request, auth.clone()).await?;
    Ok(())
}

async fn wait_server_status(
    client: &WsAdminClient,
    expected_status: ServerStatus,
) -> anyhow::Result<()> {
    const RETRIES: usize = 60;
    poll_max_retries("waiting-server-status", RETRIES, || async {
        Ok(client.status().await?.server == expected_status)
    })
    .await?;
    Ok(())
}
