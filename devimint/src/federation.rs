use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::{env, fs};

use anyhow::{anyhow, bail, Context, Result};
use bitcoincore_rpc::bitcoin::Network;
use bitcoincore_rpc::RpcApi;
use fedimint_core::admin_client::{
    ConfigGenConnectionsRequest, ConfigGenParamsRequest, WsAdminClient,
};
use fedimint_core::api::ServerStatus;
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::config::{load_from_file, ClientConfig, ServerModuleConfigGenParamsRegistry};
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_WALLET;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ApiAuth, ModuleCommon};
use fedimint_core::util::SafeUrl;
use fedimint_core::PeerId;
use fedimint_server::config::ConfigGenParams;
use fedimint_testing::federation::local_config_gen_params;
use fedimint_wallet_client::config::WalletClientConfig;
use fedimintd::attach_default_module_init_params;
use fedimintd::fedimintd::FM_EXTRA_DKG_META_VAR;
use futures::future::join_all;
use rand::Rng;
use tracing::info;

use super::external::Bitcoind;
use super::util::{cmd, parse_map, Command, ProcessHandle, ProcessManager};
use super::vars::utf8;
use crate::util::poll;
use crate::{poll_eq, vars};

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
        let params: HashMap<PeerId, ConfigGenParams> = local_config_gen_params(
            &peers,
            process_mgr.globals.FM_PORT_FEDIMINTD_BASE,
            ServerModuleConfigGenParamsRegistry::default(),
        )?;

        let mut admin_clients: BTreeMap<PeerId, WsAdminClient> = BTreeMap::new();
        for (peer, peer_params) in &params {
            let var = vars::Fedimintd::init(&process_mgr.globals, peer_params.to_owned()).await?;
            members.insert(
                peer.to_usize(),
                Fedimintd::new(process_mgr, bitcoind.clone(), peer.to_usize(), &var).await?,
            );
            let admin_client = WsAdminClient::new(SafeUrl::parse(&var.FM_API_URL)?);
            admin_clients.insert(*peer, admin_client);
            vars.insert(peer.to_usize(), var);
        }

        run_dkg(admin_clients, params).await?;

        let out_dir = &vars[&0].FM_DATA_DIR;
        let cfg_dir = &process_mgr.globals.FM_DATA_DIR;
        let out_dir = utf8(out_dir);
        let cfg_dir = utf8(cfg_dir);
        // move configs to config directory
        tokio::fs::rename(
            format!("{out_dir}/invite-code"),
            format!("{cfg_dir}/invite-code"),
        )
        .await
        .context("moving invite code file")?;
        info!("moved client configs");

        Ok(Self {
            members,
            vars,
            bitcoind,
        })
    }

    pub async fn client_config(&self) -> Result<ClientConfig> {
        let cfg_path = self.vars[&0].FM_DATA_DIR.join("client.json");
        load_from_file(&cfg_path)
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
        self.bitcoind.mine_blocks(21).await?;

        cmd!(self, "await-deposit", deposit_operation_id)
            .run()
            .await?;
        Ok(())
    }

    pub async fn pegin_gateway(&self, amount: u64, gw: &super::Gatewayd) -> Result<()> {
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

    pub async fn federation_id(&self) -> String {
        self.client_config()
            .await
            .unwrap()
            .global
            .federation_id()
            .to_string()
    }

    pub async fn await_block_sync(&self) -> Result<u64> {
        let finality_delay = self.get_finality_delay().await?;
        let bitcoind_block_count = self.bitcoind.client().get_blockchain_info()?.blocks;
        let expected = bitcoind_block_count.saturating_sub(finality_delay.into());
        cmd!(self, "dev", "wait-block-count", expected)
            .run()
            .await?;
        Ok(expected)
    }

    pub async fn generate_first_epoch(&self) -> Result<()> {
        // TODO: optimize this
        self.generate_epochs(1).await?;
        Ok(())
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
        poll("gateways registered", None, || async {
            let num_gateways = cmd!(self, "list-gateways")
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

    pub async fn use_gateway(&self, gw: &super::Gatewayd) -> Result<()> {
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
        let finality_delay = self.get_finality_delay().await?;
        for _ in 0..epochs {
            self.bitcoind.mine_blocks(finality_delay.into()).await?;
            self.await_block_sync().await?;
        }
        Ok(())
    }

    pub async fn client_balance(&self) -> Result<u64> {
        Ok(cmd!(self, "info").out_json().await?["total_amount_msat"]
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

pub async fn run_dkg(
    admin_clients: BTreeMap<PeerId, WsAdminClient>,
    params: HashMap<PeerId, ConfigGenParams>,
) -> Result<()> {
    let auth_for = |peer: &PeerId| -> ApiAuth { params[peer].local.api_auth.clone() };
    for (peer_id, client) in &admin_clients {
        const MAX_RETRIES: usize = 20;
        super::poll("trying-to-connect-to-peers", MAX_RETRIES, || async {
            client
                .status()
                .await
                .context("dkg status")
                .map_err(ControlFlow::Continue)
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
    info!("Running DKG...");
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
    info!("DKG successfully complete. Starting consensus...");
    for (peer_id, client) in &admin_clients {
        if let Err(e) = client.start_consensus(auth_for(peer_id)).await {
            tracing::info!("Error calling start_consensus: {e:?}, trying to continue...")
        }

        wait_server_status(client, ServerStatus::ConsensusRunning).await?;
    }
    info!("Consensus is running");
    Ok(())
}

async fn set_config_gen_params(
    client: &WsAdminClient,
    auth: ApiAuth,
    mut server_gen_params: ServerModuleConfigGenParamsRegistry,
) -> Result<()> {
    attach_default_module_init_params(
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

async fn wait_server_status(client: &WsAdminClient, expected_status: ServerStatus) -> Result<()> {
    const RETRIES: usize = 60;
    super::poll("waiting-server-status", RETRIES, || async {
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
    })
    .await?;
    Ok(())
}
