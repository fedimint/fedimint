use std::collections::BTreeMap;
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;
use std::{env, fs};

use anyhow::{Context, Result, bail};
use fedimint_api_client::api::DynGlobalApi;
use fedimint_api_client::download_from_invite_code;
use fedimint_client_module::module::ClientModule;
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::admin_client::SetupStatus;
use fedimint_core::config::{ClientConfig, load_from_file};
use fedimint_core::core::{ModuleInstanceId, ModuleKind};
use fedimint_core::invite_code::InviteCode;
use fedimint_core::module::ModuleCommon;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::runtime::block_in_place;
use fedimint_core::task::block_on;
use fedimint_core::task::jit::JitTryAnyhow;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, NumPeers, PeerId};
use fedimint_gateway_common::WithdrawResponse;
use fedimint_logging::LOG_DEVIMINT;
use fedimint_testing_core::config::API_AUTH;
use fedimint_testing_core::node_type::LightningNodeType;
use fedimint_wallet_client::WalletClientModule;
use fedimint_wallet_client::config::WalletClientConfig;
use fs_lock::FileLock;
use futures::future::{join_all, try_join_all};
use tokio::task::{JoinSet, spawn_blocking};
use tokio::time::Instant;
use tracing::{debug, info};

use super::external::Bitcoind;
use super::util::{Command, ProcessHandle, ProcessManager, cmd};
use super::vars::utf8;
use crate::envs::{FM_CLIENT_DIR_ENV, FM_DATA_DIR_ENV};
use crate::util::{FedimintdCmd, poll, poll_simple, poll_with_timeout};
use crate::version_constants::VERSION_0_10_0_ALPHA;
use crate::{poll_almost_equal, poll_eq, vars};

// TODO: Are we still using the 3rd port for anything?
/// Number of ports we allocate for every `fedimintd` instance
pub const PORTS_PER_FEDIMINTD: u16 = 4;
/// Which port is for p2p inside the range from [`PORTS_PER_FEDIMINTD`]
pub const FEDIMINTD_P2P_PORT_OFFSET: u16 = 0;
/// Which port is for api inside the range from [`PORTS_PER_FEDIMINTD`]
pub const FEDIMINTD_API_PORT_OFFSET: u16 = 1;
/// Which port is for the web ui inside the range from [`PORTS_PER_FEDIMINTD`]
pub const FEDIMINTD_UI_PORT_OFFSET: u16 = 2;
/// Which port is for prometheus inside the range from [`PORTS_PER_FEDIMINTD`]
pub const FEDIMINTD_METRICS_PORT_OFFSET: u16 = 3;

#[derive(Clone)]
pub struct Federation {
    // client is only for internal use, use cli commands instead
    pub members: BTreeMap<usize, Fedimintd>,
    pub vars: BTreeMap<usize, vars::Fedimintd>,
    pub bitcoind: Bitcoind,

    /// Built in [`Client`], already joined
    client: JitTryAnyhow<Client>,
    #[allow(dead_code)] // Will need it later, maybe
    connectors: ConnectorRegistry,
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

    /// Waits for the client balance to reach at least `min_balance_msat`.
    pub async fn await_balance(&self, min_balance_msat: u64) -> Result<()> {
        loop {
            cmd!(self, "dev", "wait", "3").out_json().await?;

            let balance = self.balance().await?;
            if balance >= min_balance_msat {
                return Ok(());
            }

            info!(
                target: LOG_DEVIMINT,
                balance,
                min_balance_msat,
                "Waiting for client balance to reach minimum"
            );
        }
    }

    pub async fn get_deposit_addr(&self) -> Result<(String, String)> {
        if crate::util::supports_wallet_v2() {
            let address = cmd!(self, "module", "walletv2", "receive")
                .out_json()
                .await?;
            // Walletv2 auto-claims deposits, no operation_id needed
            Ok((address.as_str().unwrap().to_string(), String::new()))
        } else {
            let deposit = cmd!(self, "deposit-address").out_json().await?;
            Ok((
                deposit["address"].as_str().unwrap().to_string(),
                deposit["operation_id"].as_str().unwrap().to_string(),
            ))
        }
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
        skip_setup: bool,
        pre_dkg: bool,
        // Which of the pre-allocated federations to use (most tests just use single `0` one)
        fed_index: usize,
        federation_name: String,
    ) -> Result<Self> {
        let num_peers = NumPeers::from(process_mgr.globals.FM_FED_SIZE);
        let mut members = BTreeMap::new();
        let mut peer_to_env_vars_map = BTreeMap::new();

        let mut admin_clients: BTreeMap<PeerId, DynGlobalApi> = BTreeMap::new();
        let mut api_endpoints: BTreeMap<PeerId, _> = BTreeMap::new();

        let connectors = ConnectorRegistry::build_from_testing_env()?.bind().await?;
        for peer_id in num_peers.peer_ids() {
            let peer_env_vars = vars::Fedimintd::init(
                &process_mgr.globals,
                federation_name.clone(),
                peer_id,
                process_mgr
                    .globals
                    .fedimintd_overrides
                    .peer_expect(fed_index, peer_id),
            )
            .await?;
            members.insert(
                peer_id.to_usize(),
                Fedimintd::new(
                    process_mgr,
                    bitcoind.clone(),
                    peer_id.to_usize(),
                    &peer_env_vars,
                    federation_name.clone(),
                )
                .await?,
            );
            let admin_client = DynGlobalApi::new_admin_setup(
                connectors.clone(),
                SafeUrl::parse(&peer_env_vars.FM_API_URL)?,
                // TODO: will need it somewhere
                // &process_mgr.globals.FM_FORCE_API_SECRETS.get_active(),
            )?;
            api_endpoints.insert(peer_id, peer_env_vars.FM_API_URL.clone());
            admin_clients.insert(peer_id, admin_client);
            peer_to_env_vars_map.insert(peer_id.to_usize(), peer_env_vars);
        }

        if !skip_setup && !pre_dkg {
            // we don't guarantee backwards-compatibility for dkg, so we use the
            // fedimint-cli version that matches fedimintd
            let (original_fedimint_cli_path, original_fm_mint_client) =
                crate::util::use_matching_fedimint_cli_for_dkg().await?;

            run_cli_dkg_v2(api_endpoints).await?;

            // we're done with dkg, so we can reset the fedimint-cli version
            crate::util::use_fedimint_cli(original_fedimint_cli_path, original_fm_mint_client);

            // move configs to config directory
            let client_dir = utf8(&process_mgr.globals.FM_CLIENT_DIR);
            let invite_code_filename_original = "invite-code";

            for peer_env_vars in peer_to_env_vars_map.values() {
                let peer_data_dir = utf8(&peer_env_vars.FM_DATA_DIR);

                let invite_code = poll_simple("awaiting-invite-code", || async {
                    let path = format!("{peer_data_dir}/{invite_code_filename_original}");
                    tokio::fs::read_to_string(&path)
                        .await
                        .with_context(|| format!("Awaiting invite code file: {path}"))
                })
                .await
                .context("Awaiting invite code file")?;

                download_from_invite_code(&connectors, &InviteCode::from_str(&invite_code)?)
                    .await?;
            }

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
                if !skip_setup && !pre_dkg {
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
            connectors,
        })
    }

    pub fn client_config(&self) -> Result<ClientConfig> {
        let cfg_path = self.vars[&0].FM_DATA_DIR.join("client.json");
        load_from_file(&cfg_path)
    }

    /// Get the module instance ID for a given module kind
    pub fn module_instance_id_by_kind(&self, kind: &ModuleKind) -> Result<ModuleInstanceId> {
        self.client_config()?
            .modules
            .iter()
            .find_map(|(id, cfg)| if &cfg.kind == kind { Some(*id) } else { None })
            .with_context(|| format!("Module kind {kind} not found"))
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
        if crate::util::supports_wallet_v2() {
            Ok(self
                .module_client_config::<fedimint_walletv2_client::WalletClientModule>()?
                .context("No walletv2 module found")?
                .fee_consensus
                .base)
        } else {
            Ok(self
                .module_client_config::<WalletClientModule>()?
                .context("No wallet module found")?
                .fee_consensus
                .peg_in_abs)
        }
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

    pub async fn await_server_terminated(&mut self, peer_id: usize) -> Result<()> {
        let Some(fedimintd) = self.members.get_mut(&peer_id) else {
            bail!("fedimintd-{peer_id} does not exist");
        };
        fedimintd.await_terminated().await?;
        self.members.remove(&peer_id);
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

        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("FM_FEDIMINTD_BASE_EXECUTABLE", bin_path) };

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
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("FM_FEDIMINTD_BASE_EXECUTABLE", bin_path) };
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("FM_FEDIMINTD_BASE_EXECUTABLE", current_fedimintd_path) };

        self.restart_all_staggered_with_bin(process_mgr, bin_path)
            .await
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

    pub async fn send_to_address(&self, address: String, amount: u64) -> Result<()> {
        self.bitcoind.send_to(address, amount).await?;

        self.bitcoind.mine_blocks(21).await?;

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
        // For walletv2, we need to capture the initial balance and wait for it to
        // increase since there is no state machine - deposits are auto-claimed
        let initial_balance = if crate::util::supports_wallet_v2() {
            Some(client.balance().await?)
        } else {
            None
        };

        let operation_id = self.pegin_client_no_wait(amount, client).await?;

        if let Some(initial) = initial_balance {
            // Walletv2: wait for balance to increase. We expect slightly less than
            // `amount` due to mint module fees when creating ecash notes.
            let expected_balance = initial + (amount * 1000 * 9 / 10);
            client.await_balance(expected_balance).await?;
        } else {
            client.await_deposit(&operation_id).await?;
        }
        Ok(())
    }

    /// Initiates multiple peg-ins to the same federation for the set of
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
        let bitcoind_block_height: u64 = self.bitcoind.get_block_count().await? - 1;
        try_join_all(gateways.into_iter().map(|gw| {
            poll("gateway pegin", || async {
                let gw_info = gw.get_info().await.map_err(ControlFlow::Continue)?;

                let block_height: u64 = if gw.gatewayd_version < *VERSION_0_10_0_ALPHA {
                    gw_info["block_height"]
                        .as_u64()
                        .expect("Could not parse block height")
                } else {
                    gw_info["lightning_info"]["connected"]["block_height"]
                        .as_u64()
                        .expect("Could not parse block height")
                };

                if bitcoind_block_height != block_height {
                    return Err(std::ops::ControlFlow::Continue(anyhow::anyhow!(
                        "gateway block height is not synced"
                    )));
                }

                let gateway_balance = gw
                    .ecash_balance(fed_id.clone())
                    .await
                    .map_err(ControlFlow::Continue)?;
                poll_almost_equal!(gateway_balance, amount * 1000)
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
            peg_outs.insert(gw.ln.ln_type(), (prev_fed_ecash_balance, response));
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

            let ln_type = gw.ln.ln_type();
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
            // Walletv2 charges a module fee on top of the on-chain fee:
            // 100 sats base + 1% of amount (amount is in msats)
            let tolerance = if crate::util::supports_wallet_v2() {
                let amount_sats = amount / 1000;
                let module_fee_sats = 100 + amount_sats / 100;
                module_fee_sats * 1000 + 2000
            } else {
                2000
            };
            crate::util::almost_equal(
                after_fed_ecash_balance.msats,
                prev_balance - amount - total_fee,
                tolerance,
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "new balance did not equal prev balance minus withdraw_amount minus fees: {}",
                    e
                )
            })?;
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

        if crate::util::supports_wallet_v2() {
            // Walletv2 doesn't have `dev wait-block-count`, poll using CLI instead
            let client = self.internal_client().await?;
            loop {
                let value = cmd!(client, "module", "walletv2", "info", "block-count")
                    .out_json()
                    .await?;
                let current: u64 = serde_json::from_value(value)?;
                if current >= expected {
                    break;
                }
                fedimint_core::task::sleep_in_test(
                    format!("Waiting for consensus block count to reach {expected}"),
                    std::time::Duration::from_secs(1),
                )
                .await;
            }
        } else {
            cmd!(
                self.internal_client().await?,
                "dev",
                "wait-block-count",
                expected
            )
            .run()
            .await?;
        }

        Ok(expected)
    }

    fn get_finality_delay(&self) -> Result<u32, anyhow::Error> {
        // Walletv2 uses a constant finality delay
        if crate::util::supports_wallet_v2() {
            return Ok(fedimint_walletv2_server::FINALITY_DELAY as u32);
        }

        let wallet_instance_id = self.module_instance_id_by_kind(&fedimint_wallet_client::KIND)?;
        let client_config = &self.client_config()?;
        let wallet_cfg = client_config
            .modules
            .get(&wallet_instance_id)
            .context("wallet module not found")?
            .clone()
            .redecode_raw(&ModuleDecoderRegistry::new([(
                wallet_instance_id,
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

        poll("gateways registered", || async {
            let num_gateways = cmd!(
                self.internal_client()
                    .await
                    .map_err(ControlFlow::Continue)?,
                "list-gateways"
            )
            .out_json()
            .await
            .map_err(ControlFlow::Continue)?
            .as_array()
            .context("invalid output")
            .map_err(ControlFlow::Break)?
            .len();

            // After version v0.10.0, the LND gateway will register twice. Once for the HTTP
            // server, and once for the iroh endpoint.
            let expected_gateways =
                if crate::util::Gatewayd::version_or_default().await < *VERSION_0_10_0_ALPHA {
                    1
                } else {
                    2
                };

            poll_eq!(num_gateways, expected_gateways)
        })
        .await?;
        debug!(target: LOG_DEVIMINT,
            elapsed_ms = %start_time.elapsed().as_millis(),
            "Gateways registered");
        Ok(())
    }

    pub async fn await_all_peers(&self) -> Result<()> {
        let (module_name, endpoint) = if crate::util::supports_wallet_v2() {
            ("walletv2", "consensus_block_count")
        } else {
            ("wallet", "block_count")
        };
        poll("Waiting for all peers to be online", || async {
            cmd!(
                self.internal_client()
                    .await
                    .map_err(ControlFlow::Continue)?,
                "dev",
                "api",
                "--module",
                module_name,
                endpoint
            )
            .run()
            .await
            .map_err(ControlFlow::Continue)?;
            Ok(())
        })
        .await
    }

    pub async fn await_peer(&self, peer_id: usize) -> Result<()> {
        poll("Waiting for all peers to be online", || async {
            cmd!(
                self.internal_client()
                    .await
                    .map_err(ControlFlow::Continue)?,
                "dev",
                "api",
                "--peer-id",
                peer_id,
                "--module",
                "wallet",
                "block_count"
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

    pub async fn await_terminated(&self) -> Result<()> {
        self.process.await_terminated().await
    }
}

pub async fn run_cli_dkg_v2(endpoints: BTreeMap<PeerId, String>) -> Result<()> {
    // Parallelize setup status checks
    let status_futures = endpoints.values().map(|endpoint| {
        let endpoint = endpoint.clone();
        async move {
            let status = poll("awaiting-setup-status-awaiting-local-params", || async {
                crate::util::FedimintCli
                    .setup_status(&API_AUTH, &endpoint)
                    .await
                    .map_err(ControlFlow::Continue)
            })
            .await
            .unwrap();

            assert_eq!(status, SetupStatus::AwaitingLocalParams);
        }
    });
    join_all(status_futures).await;

    debug!(target: LOG_DEVIMINT, "Setting local parameters...");

    // Parallelize setting local parameters
    let local_params_futures = endpoints.iter().map(|(peer, endpoint)| {
        let peer = *peer;
        let endpoint = endpoint.clone();
        async move {
            let info = if peer.to_usize() == 0 {
                crate::util::FedimintCli
                    .set_local_params_leader(&peer, &API_AUTH, &endpoint)
                    .await
            } else {
                crate::util::FedimintCli
                    .set_local_params_follower(&peer, &API_AUTH, &endpoint)
                    .await
            };
            info.map(|i| (peer, i))
        }
    });
    let connection_info: BTreeMap<_, _> = try_join_all(local_params_futures)
        .await?
        .into_iter()
        .collect();

    debug!(target: LOG_DEVIMINT, "Exchanging peer connection info...");

    // Parallelize peer addition - flatten the nested loop into a single parallel
    // operation
    let add_peer_futures = connection_info.iter().flat_map(|(peer, info)| {
        endpoints
            .iter()
            .filter(move |(p, _)| *p != peer)
            .map(move |(_, endpoint)| {
                let endpoint = endpoint.clone();
                let info = info.clone();
                async move {
                    crate::util::FedimintCli
                        .add_peer(&info, &API_AUTH, &endpoint)
                        .await
                }
            })
    });
    try_join_all(add_peer_futures).await?;

    debug!(target: LOG_DEVIMINT, "Starting DKG...");

    // Parallelize DKG start
    let start_dkg_futures = endpoints.values().map(|endpoint| {
        let endpoint = endpoint.clone();
        async move {
            crate::util::FedimintCli
                .start_dkg(&API_AUTH, &endpoint)
                .await
        }
    });
    try_join_all(start_dkg_futures).await?;

    Ok(())
}
