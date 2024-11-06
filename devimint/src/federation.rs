mod config;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::time::Duration;
use std::{env, fs, iter};

use anyhow::{anyhow, bail, Context, Result};
use bitcoincore_rpc::bitcoin::Network;
use fedimint_api_client::api::DynGlobalApi;
use fedimint_client::module::ClientModule;
use fedimint_core::admin_client::{
    ConfigGenConnectionsRequest, ConfigGenParamsRequest, ServerStatus,
};
use fedimint_core::config::{load_from_file, ClientConfig, ServerModuleConfigGenParamsRegistry};
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_WALLET;
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{ApiAuth, ModuleCommon};
use fedimint_core::runtime::block_in_place;
use fedimint_core::task::block_on;
use fedimint_core::task::jit::JitTryAnyhow;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, PeerId};
use fedimint_logging::LOG_DEVIMINT;
use fedimint_portalloc::port_alloc;
use fedimint_server::config::ConfigGenParams;
use fedimint_testing::federation::local_config_gen_params;
use fedimint_testing::gateway::LightningNodeType;
use fedimint_wallet_client::config::WalletClientConfig;
use fedimint_wallet_client::WalletClientModule;
use fedimintd::envs::FM_EXTRA_DKG_META_ENV;
use fs_lock::FileLock;
use futures::future::{join_all, try_join_all};
use ln_gateway::rpc::WithdrawResponse;
use rand::Rng;
use tokio::task::{spawn_blocking, JoinSet};
use tokio::time::Instant;
use tracing::{debug, info};

use super::external::Bitcoind;
use super::util::{cmd, parse_map, Command, ProcessHandle, ProcessManager};
use super::vars::utf8;
use crate::envs::{FM_CLIENT_DIR_ENV, FM_DATA_DIR_ENV};
use crate::util::{poll, poll_with_timeout, FedimintdCmd};
use crate::version_constants::{VERSION_0_3_0, VERSION_0_3_0_ALPHA};
use crate::{poll_eq, vars};

#[derive(Clone)]
pub struct Federation {
    // client is only for internal use, use cli commands instead
    pub members: BTreeMap<usize, Fedimintd>,
    pub vars: BTreeMap<usize, vars::Fedimintd>,
    pub bitcoind: Bitcoind,

    /// Built in [`Client`], already joined
    client: JitTryAnyhow<Client>,
}

impl Drop for Federation {
    fn drop(&mut self) {
        block_in_place(|| {
            block_on(async {
                let mut set = JoinSet::new();

                while let Some((_id, fedimintd)) = self.members.pop_first() {
                    set.spawn(async { drop(fedimintd) });
                }
                while (set.join_next().await).is_some() {}
            });
        });
    }
}
/// `fedimint-cli` instance (basically path with client state: config + db)
#[derive(Clone)]
pub struct Client {
    name: String,
}

impl Client {
    fn clients_dir() -> PathBuf {
        let data_dir: PathBuf = env::var(FM_DATA_DIR_ENV)
            .expect("FM_DATA_DIR_ENV not set")
            .parse()
            .expect("FM_DATA_DIR_ENV invalid");
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
    pub async fn create(name: impl ToString) -> Result<Client> {
        let name = name.to_string();
        spawn_blocking(move || {
            let _lock = Self::client_name_lock(&name);
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
        .await?
    }

    /// Open or create a [`Client`] that starts with a fresh state.
    pub fn open_or_create(name: &str) -> Result<Client> {
        block_in_place(|| {
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

    /// Client to join a federation with a restore procedure
    pub async fn restore_federation(&self, invite_code: String, mnemonic: String) -> Result<()> {
        debug!(target: LOG_DEVIMINT, "Joining federation with restore procedure");
        cmd!(
            self,
            "restore",
            "--invite-code",
            invite_code,
            "--mnemonic",
            mnemonic
        )
        .run()
        .await?;

        Ok(())
    }

    /// Client to join a federation
    pub async fn new_restored(&self, name: &str, invite_code: String) -> Result<Self> {
        let restored = Self::open_or_create(name)?;

        let mnemonic = cmd!(self, "print-secret").out_json().await?["secret"]
            .as_str()
            .unwrap()
            .to_owned();

        debug!(target: LOG_DEVIMINT, name, "Restoring from mnemonic");
        cmd!(
            restored,
            "restore",
            "--invite-code",
            invite_code,
            "--mnemonic",
            mnemonic
        )
        .run()
        .await?;

        Ok(restored)
    }

    /// Create a [`Client`] that starts with a state that is a copy of
    /// of another one.
    pub async fn new_forked(&self, name: impl ToString) -> Result<Client> {
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
        if fedimint_cli_version < *VERSION_0_3_0_ALPHA {
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

    pub fn cmd(&self) -> Command {
        cmd!(
            crate::util::get_fedimint_cli_path(),
            format!("--data-dir={}", self.client_dir().display())
        )
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns the current consensus session count
    pub async fn get_session_count(&self) -> Result<u64> {
        cmd!(self, "dev", "session-count").out_json().await?["count"]
            .as_u64()
            .context("count field wasn't a number")
    }

    /// Returns once all active state machines complete
    pub async fn wait_complete(&self) -> Result<()> {
        cmd!(self, "dev", "wait-complete").run().await
    }

    /// Returns once the current session completes
    pub async fn wait_session(&self) -> anyhow::Result<()> {
        info!("Waiting for a new session");
        let session_count = self.get_session_count().await?;
        self.wait_session_outcome(session_count).await?;
        Ok(())
    }

    /// Returns once the provided session count completes
    pub async fn wait_session_outcome(&self, session_count: u64) -> anyhow::Result<()> {
        let timeout = {
            let current_session_count = self.get_session_count().await?;
            let sessions_to_wait = session_count.saturating_sub(current_session_count) + 1;
            let session_duration_seconds = 180;
            Duration::from_secs(sessions_to_wait * session_duration_seconds)
        };

        let start = Instant::now();
        poll_with_timeout("Waiting for a new session", timeout, || async {
            info!("Awaiting session outcome {session_count}");
            match cmd!(self, "dev", "api", "await_session_outcome", session_count)
                .run()
                .await
            {
                Err(e) => Err(ControlFlow::Continue(e)),
                Ok(()) => Ok(()),
            }
        })
        .await?;

        let session_found_in = start.elapsed();
        info!("session found in {session_found_in:?}");
        Ok(())
    }
}

impl Federation {
    pub async fn new(
        process_mgr: &ProcessManager,
        bitcoind: Bitcoind,
        servers: usize,
        skip_setup: bool,
        federation_name: String,
    ) -> Result<Self> {
        let mut members = BTreeMap::new();
        let mut peer_to_env_vars_map = BTreeMap::new();

        let peers: Vec<_> = (0..servers).map(|id| PeerId::from(id as u16)).collect();
        let base_port = port_alloc((3 * servers).try_into().unwrap())?;
        let params: HashMap<PeerId, ConfigGenParams> = local_config_gen_params(
            &peers,
            base_port,
            &ServerModuleConfigGenParamsRegistry::default(),
        )?;

        let mut admin_clients: BTreeMap<PeerId, DynGlobalApi> = BTreeMap::new();
        let mut endpoints: BTreeMap<PeerId, _> = BTreeMap::new();
        for (peer, peer_params) in &params {
            let peer_env_vars = vars::Fedimintd::init(
                &process_mgr.globals,
                peer_params.to_owned(),
                federation_name.clone(),
                base_port,
            )
            .await?;
            members.insert(
                peer.to_usize(),
                Fedimintd::new(
                    process_mgr,
                    bitcoind.clone(),
                    peer.to_usize(),
                    &peer_env_vars,
                    federation_name.clone(),
                )
                .await?,
            );
            let admin_client = DynGlobalApi::from_pre_peer_id_admin_endpoint(
                SafeUrl::parse(&peer_env_vars.FM_API_URL)?,
                &process_mgr.globals.FM_FORCE_API_SECRETS.get_active(),
            );
            endpoints.insert(*peer, peer_env_vars.FM_API_URL.clone());
            admin_clients.insert(*peer, admin_client);
            peer_to_env_vars_map.insert(peer.to_usize(), peer_env_vars);
        }

        if !skip_setup {
            let fedimint_cli_version = crate::util::FedimintCli::version_or_default().await;
            if fedimint_cli_version >= *VERSION_0_3_0_ALPHA {
                run_cli_dkg(params, endpoints).await?;
            } else {
                // TODO(support:v0.2): old fedimint-cli can't do DKG commands. keep this old DKG
                // setup while fedimint-cli <= v0.2.x is supported
                run_client_dkg(admin_clients, params).await?;
            }

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

                let invite_code_filename_indexed =
                    format!("{invite_code_filename_original}-{index}");
                tokio::fs::rename(
                    format!("{peer_data_dir}/{invite_code_filename_original}"),
                    format!("{client_dir}/{invite_code_filename_indexed}"),
                )
                .await
                .context("moving invite-code file")?;
            }
            debug!("Moved invite-code files to client data directory");
        }

        let client = JitTryAnyhow::new_try({
            move || async move {
                let client = Client::open_or_create(federation_name.as_str())?;
                let invite_code = Self::invite_code_static()?;
                if !skip_setup {
                    cmd!(client, "join-federation", invite_code).run().await?;
                }
                Ok(client)
            }
        });

        Ok(Self {
            members,
            vars: peer_to_env_vars_map,
            bitcoind,
            client,
        })
    }

    pub fn client_config(&self) -> Result<ClientConfig> {
        let cfg_path = self.vars[&0].FM_DATA_DIR.join("client.json");
        load_from_file(&cfg_path)
    }

    pub fn module_client_config<M: ClientModule>(
        &self,
    ) -> Result<Option<<M::Common as ModuleCommon>::ClientConfig>> {
        self.client_config()?
            .modules
            .iter()
            .find_map(|(module_instance_id, module_cfg)| {
                if module_cfg.kind == M::kind() {
                    let decoders = ModuleDecoderRegistry::new(vec![(
                        *module_instance_id,
                        M::kind(),
                        M::decoder(),
                    )]);
                    Some(
                        module_cfg
                            .config
                            .clone()
                            .redecode_raw(&decoders)
                            .expect("Decoding client cfg failed")
                            .expect_decoded_ref()
                            .as_any()
                            .downcast_ref::<<M::Common as ModuleCommon>::ClientConfig>()
                            .cloned()
                            .context("Cast to module config failed"),
                    )
                } else {
                    None
                }
            })
            .transpose()
    }

    pub fn deposit_fees(&self) -> Result<Amount> {
        Ok(self
            .module_client_config::<WalletClientModule>()?
            .context("No wallet module found")?
            .fee_consensus
            .peg_in_abs)
    }

    /// Read the invite code from the client data dir
    pub fn invite_code(&self) -> Result<String> {
        let data_dir: PathBuf = env::var(FM_CLIENT_DIR_ENV)?.parse()?;
        let invite_code = fs::read_to_string(data_dir.join("invite-code"))?;
        Ok(invite_code)
    }

    pub fn invite_code_static() -> Result<String> {
        let data_dir: PathBuf = env::var(FM_CLIENT_DIR_ENV)?.parse()?;
        let invite_code = fs::read_to_string(data_dir.join("invite-code"))?;
        Ok(invite_code)
    }
    pub fn invite_code_for(peer_id: PeerId) -> Result<String> {
        let data_dir: PathBuf = env::var(FM_CLIENT_DIR_ENV)?.parse()?;
        let name = format!("invite-code-{peer_id}");
        let invite_code = fs::read_to_string(data_dir.join(name))?;
        Ok(invite_code)
    }

    /// Built-in, default, internal [`Client`]
    ///
    /// We should be moving away from using it for anything.
    pub async fn internal_client(&self) -> Result<&Client> {
        self.client
            .get_try()
            .await
            .context("Internal client joining Federation")
    }

    /// New [`Client`] that already joined `self`
    pub async fn new_joined_client(&self, name: impl ToString) -> Result<Client> {
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
            Fedimintd::new(
                process_mgr,
                self.bitcoind.clone(),
                peer,
                &self.vars[&peer],
                "default".to_string(),
            )
            .await?,
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

    /// Starts all peers not currently running.
    pub async fn start_all_servers(&mut self, process_mgr: &ProcessManager) -> Result<()> {
        info!("starting all servers");
        let fed_size = process_mgr.globals.FM_FED_SIZE;
        for peer_id in 0..fed_size {
            if self.members.contains_key(&peer_id) {
                continue;
            }
            self.start_server(process_mgr, peer_id).await?;
        }
        self.await_all_peers().await?;
        Ok(())
    }

    /// Terminates all running peers.
    pub async fn terminate_all_servers(&mut self) -> Result<()> {
        info!("terminating all servers");
        let running_peer_ids: Vec<_> = self.members.keys().copied().collect();
        for peer_id in running_peer_ids {
            self.terminate_server(peer_id).await?;
        }
        Ok(())
    }

    /// Coordinated shutdown of all peers that restart using the provided
    /// `bin_path`. Returns `Ok()` once all peers are online.
    ///
    /// Staggering the restart more closely simulates upgrades in the wild.
    pub async fn restart_all_staggered_with_bin(
        &mut self,
        process_mgr: &ProcessManager,
        bin_path: &PathBuf,
    ) -> Result<()> {
        let fed_size = process_mgr.globals.FM_FED_SIZE;

        // ensure all peers are online
        self.start_all_servers(process_mgr).await?;

        // staggered shutdown of peers
        while self.num_members() > 0 {
            self.terminate_server(self.num_members() - 1).await?;
            if self.num_members() > 0 {
                fedimint_core::task::sleep_in_test(
                    "waiting to shutdown remaining peers",
                    Duration::from_secs(10),
                )
                .await;
            }
        }

        std::env::set_var("FM_FEDIMINTD_BASE_EXECUTABLE", bin_path);

        // staggered restart
        for peer_id in 0..fed_size {
            self.start_server(process_mgr, peer_id).await?;
            if peer_id < fed_size - 1 {
                fedimint_core::task::sleep_in_test(
                    "waiting to restart remaining peers",
                    Duration::from_secs(10),
                )
                .await;
            }
        }

        self.await_all_peers().await?;

        let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;
        info!("upgraded fedimintd to version: {}", fedimintd_version);
        Ok(())
    }

    pub async fn restart_all_with_bin_after_session(
        &mut self,
        process_mgr: &ProcessManager,
        bin_path: &PathBuf,
    ) -> Result<()> {
        // devimint defines `FM_SKIP_REL_NOTES_ACK` during setup, so we need to remove
        // to verify the logic for `FM_REL_NOTES_ACK` works
        std::env::remove_var("FM_SKIP_REL_NOTES_ACK");
        let fed_size = process_mgr.globals.FM_FED_SIZE;

        // ensure all peers are online, which must happen for a coordinated shutdown
        self.start_all_servers(process_mgr).await?;

        let client = self.client.get_try().await?;

        // shutdown after the current session finishes
        let shutdown_after_session = client.get_session_count().await?;

        // schedule shutdown for all peers
        for peer_id in 0..self.num_members() {
            let auth = ApiAuth("pass".to_string());
            crate::util::FedimintCli
                .shutdown(&auth, peer_id.try_into()?, shutdown_after_session)
                .await?;
        }

        client.wait_session_outcome(shutdown_after_session).await?;

        poll_with_timeout(
            "waiting for all peers to finish scheduled shutdown",
            // fedimintd will wait 60s to shutdown, so we include a buffer
            Duration::from_secs(70),
            || async {
                for peer_id in 0..self.num_members() {
                    let auth = ApiAuth("pass".to_string());
                    if crate::util::FedimintCli
                        .status(&auth, peer_id.try_into().expect("conversion to u64 works"))
                        .await
                        .is_ok()
                    {
                        return Err(ControlFlow::Continue(anyhow!("peer is still running")));
                    }
                }
                Ok(())
            },
        )
        .await?;

        // we need to cleanup all the processes for the shutdown peers
        for peer_id in 0..self.num_members() {
            self.terminate_server(peer_id).await?;
        }

        std::env::set_var("FM_FEDIMINTD_BASE_EXECUTABLE", bin_path);
        std::env::set_var("FM_REL_NOTES_ACK", "0_4_xyz");

        // staggered restart
        for peer_id in 0..fed_size {
            self.start_server(process_mgr, peer_id).await?;
            if peer_id < fed_size - 1 {
                fedimint_core::task::sleep_in_test(
                    "waiting to restart remaining peers",
                    Duration::from_secs(10),
                )
                .await;
            }
        }

        self.await_all_peers().await?;

        let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;
        info!("upgraded fedimintd to version: {}", fedimintd_version);
        Ok(())
    }

    pub async fn restart_all_with_bin(
        &mut self,
        process_mgr: &ProcessManager,
        bin_path: &PathBuf,
    ) -> Result<()> {
        // get the version we're upgrading to, temporarily updating the fedimintd path
        let current_fedimintd_path = std::env::var("FM_FEDIMINTD_BASE_EXECUTABLE")?;
        std::env::set_var("FM_FEDIMINTD_BASE_EXECUTABLE", bin_path);
        let new_fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;
        std::env::set_var("FM_FEDIMINTD_BASE_EXECUTABLE", current_fedimintd_path);

        if Self::version_requires_coordinated_shutdown(&new_fedimintd_version) {
            self.restart_all_with_bin_after_session(process_mgr, bin_path)
                .await
        } else {
            self.restart_all_staggered_with_bin(process_mgr, bin_path)
                .await
        }
    }

    fn version_requires_coordinated_shutdown(version: &semver::Version) -> bool {
        matches!((version.major, version.minor), (0, 4 | 5))
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

    pub async fn pegin_client_no_wait(&self, amount: u64, client: &Client) -> Result<String> {
        let deposit_fees_msat = self.deposit_fees()?.msats;
        assert_eq!(
            deposit_fees_msat % 1000,
            0,
            "Deposit fees expected to be whole sats in test suite"
        );
        let deposit_fees = deposit_fees_msat / 1000;
        info!(amount, deposit_fees, "Pegging-in client funds");

        let (address, operation_id) = client.get_deposit_addr().await?;

        self.bitcoind
            .send_to(address, amount + deposit_fees)
            .await?;
        self.bitcoind.mine_blocks(21).await?;

        Ok(operation_id)
    }

    pub async fn pegin_client(&self, amount: u64, client: &Client) -> Result<()> {
        let operation_id = self.pegin_client_no_wait(amount, client).await?;

        client.await_deposit(&operation_id).await?;
        Ok(())
    }

    /// Inititates multiple peg-ins to the same federation for the set of
    /// gateways to save on mining blocks in parallel.
    pub async fn pegin_gateways(
        &self,
        amount: u64,
        gateways: Vec<&super::gatewayd::Gatewayd>,
    ) -> Result<()> {
        let deposit_fees_msat = self.deposit_fees()?.msats;
        assert_eq!(
            deposit_fees_msat % 1000,
            0,
            "Deposit fees expected to be whole sats in test suite"
        );
        let deposit_fees = deposit_fees_msat / 1000;
        info!(amount, deposit_fees, "Pegging-in gateway funds");
        let fed_id = self.calculate_federation_id();
        for gw in gateways.clone() {
            let pegin_addr = gw.get_pegin_addr(&fed_id).await?;
            self.bitcoind
                .send_to(pegin_addr, amount + deposit_fees)
                .await?;
        }

        self.bitcoind.mine_blocks(21).await?;
        try_join_all(gateways.into_iter().map(|gw| {
            poll("gateway pegin", || async {
                let gateway_balance = gw
                    .ecash_balance(fed_id.clone())
                    .await
                    .map_err(ControlFlow::Continue)?;
                poll_eq!(gateway_balance, amount * 1000)
            })
        }))
        .await?;

        Ok(())
    }

    /// Initiates multiple peg-outs from the same federation for the set of
    /// gateways to save on mining blocks in parallel.
    pub async fn pegout_gateways(
        &self,
        amount: u64,
        gateways: Vec<&super::gatewayd::Gatewayd>,
    ) -> Result<()> {
        info!(amount, "Pegging-out gateway funds");
        let fed_id = self.calculate_federation_id();
        let mut peg_outs: BTreeMap<LightningNodeType, (Amount, WithdrawResponse)> = BTreeMap::new();
        for gw in gateways.clone() {
            let prev_fed_ecash_balance = gw
                .get_balances()
                .await?
                .ecash_balances
                .into_iter()
                .find(|fed| fed.federation_id.to_string() == fed_id)
                .expect("Gateway has not joined federation")
                .ecash_balance_msats;

            let pegout_address = self.bitcoind.get_new_address().await?;
            let value = cmd!(
                gw,
                "ecash",
                "pegout",
                "--federation-id",
                fed_id,
                "--amount",
                amount,
                "--address",
                pegout_address
            )
            .out_json()
            .await?;
            let response: WithdrawResponse = serde_json::from_value(value)?;
            peg_outs.insert(gw.ln_type(), (prev_fed_ecash_balance, response));
        }
        self.bitcoind.mine_blocks(21).await?;

        try_join_all(
            peg_outs
                .values()
                .map(|(_, pegout)| self.bitcoind.poll_get_transaction(pegout.txid)),
        )
        .await?;

        for gw in gateways.clone() {
            let after_fed_ecash_balance = gw
                .get_balances()
                .await?
                .ecash_balances
                .into_iter()
                .find(|fed| fed.federation_id.to_string() == fed_id)
                .expect("Gateway has not joined federation")
                .ecash_balance_msats;
            let ln_type = gw.ln_type();
            let prev_balance = peg_outs
                .get(&ln_type)
                .expect("peg out does not exist")
                .0
                .msats;
            let fees = peg_outs
                .get(&ln_type)
                .expect("peg out does not exist")
                .1
                .fees;
            let total_fee = fees.amount().to_sat() * 1000;
            assert_eq!(
                prev_balance - amount - total_fee,
                after_fed_ecash_balance.msats,
                "new balance did not equal prev balance minus withdraw_amount minus fees"
            );
        }

        Ok(())
    }

    pub fn calculate_federation_id(&self) -> String {
        self.client_config()
            .unwrap()
            .global
            .calculate_federation_id()
            .to_string()
    }

    pub async fn await_block_sync(&self) -> Result<u64> {
        let finality_delay = self.get_finality_delay()?;
        let block_count = self.bitcoind.get_block_count().await?;
        let expected = block_count.saturating_sub(finality_delay.into());
        cmd!(
            self.internal_client().await?,
            "dev",
            "wait-block-count",
            expected
        )
        .run()
        .await?;
        Ok(expected)
    }

    fn get_finality_delay(&self) -> Result<u32, anyhow::Error> {
        let client_config = &self.client_config()?;
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
        // TODO(support:v0.3.0): remove
        // update-gateway-cache exists only for v0.3.0
        let command = if fedimint_cli_version == *VERSION_0_3_0 {
            "update-gateway-cache"
        } else {
            "list-gateways"
        };

        poll("gateways registered", || async {
            let num_gateways = cmd!(
                self.internal_client()
                    .await
                    .map_err(ControlFlow::Continue)?,
                command
            )
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
        poll("Waiting for all peers to be online", || async {
            cmd!(
                self.internal_client()
                    .await
                    .map_err(ControlFlow::Continue)?,
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
        let finality_delay = self.get_finality_delay()?;
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

    pub fn member_ids(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.members
            .keys()
            .map(|&peer_id| PeerId::from(peer_id as u16))
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
        fed_name: String,
    ) -> Result<Self> {
        debug!(target: LOG_DEVIMINT, "Starting fedimintd-{fed_name}-{peer_id}");
        let process = process_mgr
            .spawn_daemon(
                &format!("fedimintd-{fed_name}-{peer_id}"),
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

pub async fn run_cli_dkg(
    params: HashMap<PeerId, ConfigGenParams>,
    endpoints: BTreeMap<PeerId, String>,
) -> Result<()> {
    let auth_for = |peer: &PeerId| -> &ApiAuth { &params[peer].local.api_auth };

    debug!(target: LOG_DEVIMINT, "Running DKG");
    for endpoint in endpoints.values() {
        poll("trying-to-connect-to-peers", || async {
            crate::util::FedimintCli
                .ws_status(endpoint)
                .await
                .context("dkg status")
                .map_err(ControlFlow::Continue)
        })
        .await?;
    }

    debug!(target: LOG_DEVIMINT, "Connected to all peers");

    for (peer_id, endpoint) in &endpoints {
        let status = crate::util::FedimintCli.ws_status(endpoint).await?;
        assert_eq!(
            status.server,
            ServerStatus::AwaitingPassword,
            "peer_id isn't waiting for password: {peer_id}"
        );
    }

    debug!(target: LOG_DEVIMINT, "Setting passwords");
    for (peer_id, endpoint) in &endpoints {
        crate::util::FedimintCli
            .set_password(auth_for(peer_id), endpoint)
            .await?;
    }
    let (leader_id, leader_endpoint) = endpoints.first_key_value().context("missing peer")?;
    let followers = endpoints
        .iter()
        .filter(|(id, _)| *id != leader_id)
        .collect::<BTreeMap<_, _>>();

    debug!(target: LOG_DEVIMINT, "calling set_config_gen_connections for leader");
    let leader_name = "leader".to_string();
    crate::util::FedimintCli
        .set_config_gen_connections(auth_for(leader_id), leader_endpoint, &leader_name, None)
        .await?;

    crate::util::FedimintCli
        .get_default_config_gen_params(auth_for(leader_id), leader_endpoint)
        .await?; // sanity check

    let server_gen_params = &params[leader_id].consensus.modules;

    debug!(target: LOG_DEVIMINT, "calling set_config_gen_params for leader");
    cli_set_config_gen_params(
        leader_endpoint,
        auth_for(leader_id),
        server_gen_params.clone(),
    )
    .await?;

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
    for (peer_id, endpoint) in &followers {
        let name = followers_names
            .get(peer_id)
            .context("missing follower name")?;
        debug!(target: LOG_DEVIMINT, "calling set_config_gen_connections for {peer_id} {name}");

        crate::util::FedimintCli
            .set_config_gen_connections(auth_for(peer_id), endpoint, name, Some(leader_endpoint))
            .await?;

        cli_set_config_gen_params(endpoint, auth_for(peer_id), server_gen_params.clone()).await?;
    }

    debug!(target: LOG_DEVIMINT, "calling get_config_gen_peers for leader");
    let peers = crate::util::FedimintCli
        .get_config_gen_peers(leader_endpoint)
        .await?;

    let found_names = peers
        .into_iter()
        .map(|peer| peer.name)
        .collect::<HashSet<_>>();
    let all_names = followers_names
        .values()
        .cloned()
        .chain(iter::once(leader_name))
        .collect::<HashSet<_>>();
    assert_eq!(found_names, all_names);

    debug!(target: LOG_DEVIMINT, "Waiting for SharingConfigGenParams");
    cli_wait_server_status(leader_endpoint, ServerStatus::SharingConfigGenParams).await?;

    debug!(target: LOG_DEVIMINT, "Getting consensus configs");
    let mut configs = vec![];
    for endpoint in endpoints.values() {
        let config = crate::util::FedimintCli
            .consensus_config_gen_params(endpoint)
            .await?;
        configs.push(config);
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
    assert_eq!(ids.len(), endpoints.len());
    let dkg_results = endpoints
        .iter()
        .map(|(peer_id, endpoint)| crate::util::FedimintCli.run_dkg(auth_for(peer_id), endpoint));
    debug!(target: LOG_DEVIMINT, "Running DKG");
    let (dkg_results, leader_wait_result) = tokio::join!(
        join_all(dkg_results),
        cli_wait_server_status(leader_endpoint, ServerStatus::VerifyingConfigs)
    );
    for result in dkg_results {
        result?;
    }
    leader_wait_result?;

    // verify config hashes equal for all peers
    debug!(target: LOG_DEVIMINT, "Verifying config hashes");
    let mut hashes = HashSet::new();
    for (peer_id, endpoint) in &endpoints {
        cli_wait_server_status(endpoint, ServerStatus::VerifyingConfigs).await?;
        let hash = crate::util::FedimintCli
            .get_verify_config_hash(auth_for(peer_id), endpoint)
            .await?;
        hashes.insert(hash);
    }
    assert_eq!(hashes.len(), 1);
    info!(target: LOG_DEVIMINT, "DKG completed");
    debug!(target: LOG_DEVIMINT, "Starting consensus");
    for (peer_id, endpoint) in &endpoints {
        let result = crate::util::FedimintCli
            .start_consensus(auth_for(peer_id), endpoint)
            .await;
        if let Err(e) = result {
            tracing::debug!(target: LOG_DEVIMINT, "Error calling start_consensus: {e:?}, trying to continue...");
        }
        cli_wait_server_status(endpoint, ServerStatus::ConsensusRunning).await?;
    }
    info!(target: LOG_DEVIMINT, "Consensus running");
    Ok(())
}

pub async fn run_client_dkg(
    admin_clients: BTreeMap<PeerId, DynGlobalApi>,
    params: HashMap<PeerId, ConfigGenParams>,
) -> Result<()> {
    let auth_for = |peer: &PeerId| -> ApiAuth { params[peer].local.api_auth.clone() };
    for (peer_id, client) in &admin_clients {
        poll("trying-to-connect-to-peers", || async {
            client
                .status()
                .await
                .context("dkg status")
                .map_err(ControlFlow::Continue)
        })
        .await?;
        debug!(target: LOG_DEVIMINT, "Connected to {peer_id}");
    }

    for (peer_id, client) in &admin_clients {
        assert_eq!(
            client.status().await?.server,
            ServerStatus::AwaitingPassword,
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

    // Note: names prefixed by peerid, as DKG sort peers by submitted name
    // by default.
    let leader_name = format!("{leader_id}-leader");
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
                format!("{peer_id}-random-{random_string}{peer_id}")
            })
        })
        .collect::<BTreeMap<_, _>>();
    for (peer_id, client) in &followers {
        let name = followers_names
            .get(peer_id)
            .context("missing follower name")?;
        debug!(target: LOG_DEVIMINT, "calling set_config_gen_connections for {peer_id} {name}");
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
    debug!(target: LOG_DEVIMINT, "Running DKG");
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
    info!(target: LOG_DEVIMINT, "DKG completed");
    debug!(target: LOG_DEVIMINT, "Starting consensus");
    for (peer_id, client) in &admin_clients {
        if let Err(e) = client.start_consensus(auth_for(peer_id)).await {
            tracing::debug!(target: LOG_DEVIMINT, "Error calling start_consensus: {e:?}, trying to continue...");
        }
        wait_server_status(client, ServerStatus::ConsensusRunning).await?;
    }
    info!(target: LOG_DEVIMINT, "Consensus running");
    Ok(())
}

async fn set_config_gen_params(
    client: &DynGlobalApi,
    auth: ApiAuth,
    mut server_gen_params: ServerModuleConfigGenParamsRegistry,
) -> Result<()> {
    // TODO(support:v0.3): v0.4 introduced lnv2 modules, so we need to skip
    // attaching the module for old fedimintd versions
    let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;
    self::config::attach_default_module_init_params(
        &BitcoinRpcConfig::get_defaults_from_env_vars()?,
        &mut server_gen_params,
        Network::Regtest,
        10,
        &fedimintd_version,
    );
    // Since we are not actually calling `fedimintd` binary, parse and handle
    // `FM_EXTRA_META_DATA` like it would do.
    let mut extra_meta_data = parse_map(
        &std::env::var(FM_EXTRA_DKG_META_ENV)
            .ok()
            .unwrap_or_default(),
    )
    .with_context(|| format!("Failed to parse {FM_EXTRA_DKG_META_ENV}"))
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

async fn cli_set_config_gen_params(
    endpoint: &str,
    auth: &ApiAuth,
    mut server_gen_params: ServerModuleConfigGenParamsRegistry,
) -> Result<()> {
    // TODO(support:v0.3): v0.4 introduced lnv2 modules, so we need to skip
    // attaching the module for old fedimintd versions
    let fedimintd_version = crate::util::FedimintdCmd::version_or_default().await;
    self::config::attach_default_module_init_params(
        &BitcoinRpcConfig::get_defaults_from_env_vars()?,
        &mut server_gen_params,
        Network::Regtest,
        10,
        &fedimintd_version,
    );
    // Since we are not actually calling `fedimintd` binary, parse and handle
    // `FM_EXTRA_META_DATA` like it would do.
    let extra_meta_data = parse_map(
        &std::env::var(FM_EXTRA_DKG_META_ENV)
            .ok()
            .unwrap_or_default(),
    )
    .with_context(|| format!("Failed to parse {FM_EXTRA_DKG_META_ENV}"))
    .expect("Failed");
    let meta: BTreeMap<String, String> =
        iter::once(("federation_name".to_string(), "testfed".to_string()))
            .chain(extra_meta_data)
            .collect();

    crate::util::FedimintCli
        .set_config_gen_params(auth, endpoint, meta, server_gen_params)
        .await?;
    Ok(())
}

async fn wait_server_status(client: &DynGlobalApi, expected_status: ServerStatus) -> Result<()> {
    poll(
        &format!("waiting-server-status: {expected_status:?}"),
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

async fn cli_wait_server_status(endpoint: &str, expected_status: ServerStatus) -> Result<()> {
    poll(
        &format!("waiting-server-status: {expected_status:?}"),
        || async {
            let server_status = crate::util::FedimintCli
                .ws_status(endpoint)
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
