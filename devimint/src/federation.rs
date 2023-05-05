use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

use anyhow::{anyhow, Context};
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_WALLET;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::task::TaskGroup;
use fedimint_wallet_client::config::WalletClientConfig;
use tokio::fs;
use tokio::sync::mpsc::{self, Receiver, Sender};

use super::*; // TODO: remove this

/// Create a map of environment variables which fedimintd and DKG can use,
/// but which can't be defined by `build.sh` because multiple of these daemons
/// run concurrently with different values.
///
/// We allow ranges of 10 ports for each fedimintd / dkg instance starting from
/// 18173. Each port needed is incremented by 1 within this range.
///
/// * `peer_id` - ID of the server. Used to calculate port numbers.
pub fn fedimint_env(peer_id: usize) -> anyhow::Result<HashMap<String, String>> {
    let base_port = 8173 + 10000;
    let p2p_port = base_port + (peer_id * 10);
    let api_port = base_port + (peer_id * 10) + 1;
    let ui_port = base_port + (peer_id * 10) + 2;
    let cfg_dir = env::var("FM_DATA_DIR")?;
    Ok(HashMap::from_iter([
        ("FM_BIND_P2P".into(), format!("127.0.0.1:{p2p_port}")),
        (
            "FM_P2P_URL".into(),
            format!("fedimint://127.0.0.1:{p2p_port}"),
        ),
        ("FM_BIND_API".into(), format!("127.0.0.1:{api_port}")),
        ("FM_API_URL".into(), format!("ws://127.0.0.1:{api_port}")),
        ("FM_LISTEN_UI".into(), format!("127.0.0.1:{ui_port}")),
        (
            "FM_FEDIMINT_DATA_DIR".into(),
            format!("{cfg_dir}/server-{peer_id}"),
        ),
        ("FM_PASSWORD".into(), format!("pass{peer_id}")),
    ]))
}

pub struct Federation {
    // client is only for internal use, use cli commands instead
    client: Arc<UserClient>,
    members: BTreeMap<usize, Fedimintd>,
    bitcoind: Bitcoind,
}

impl Federation {
    pub async fn new(
        process_mgr: &ProcessManager,
        bitcoind: Bitcoind,
        ids: Range<usize>,
    ) -> Result<Self> {
        let mut members = BTreeMap::new();
        for id in ids {
            members.insert(id, Fedimintd::new(process_mgr, bitcoind.clone(), id).await?);
        }

        let workdir: PathBuf = env::var("FM_DATA_DIR")?.parse()?;
        let cfg_path = workdir.join("client.json");
        let cfg: UserClientConfig = load_from_file(&cfg_path)?;
        let decoders = module_decode_stubs();
        let db = Database::new(MemDatabase::new(), module_decode_stubs());
        let module_gens = ClientModuleGenRegistry::from(vec![
            DynClientModuleGen::from(WalletClientGen),
            DynClientModuleGen::from(MintClientGen),
            DynClientModuleGen::from(LightningClientGen),
        ]);
        let client = UserClient::new(cfg, decoders, module_gens, db, Default::default()).await;
        Ok(Self {
            members,
            bitcoind,
            client: Arc::new(client),
        })
    }

    pub async fn start_server(
        &mut self,
        process_mgr: &ProcessManager,
        peer_id: usize,
    ) -> Result<()> {
        if self.members.contains_key(&peer_id) {
            return Err(anyhow!("fedimintd-{} already running", peer_id));
        }
        self.members.insert(
            peer_id,
            Fedimintd::new(process_mgr, self.bitcoind.clone(), peer_id).await?,
        );
        Ok(())
    }

    pub async fn kill_server(&mut self, peer_id: usize) -> Result<()> {
        let Some((_, fedimintd)) = self.members.remove_entry(&peer_id) else {
            return Err(anyhow!("fedimintd-{} does not exist", peer_id));
        };
        fedimintd.kill().await?;
        Ok(())
    }

    pub fn members(&self) -> &BTreeMap<usize, Fedimintd> {
        &self.members
    }

    pub async fn cmd(&self) -> Command {
        let cfg_dir = env::var("FM_DATA_DIR").unwrap();
        cmd!("fedimint-cli", "--data-dir={cfg_dir}")
    }

    pub async fn pegin(&self, amt: u64) -> Result<()> {
        let pegin_addr = cmd!(self, "peg-in-address").out_json().await?["address"]
            .as_str()
            .context("address must be a string")?
            .to_owned();
        let txid = self.bitcoind.send_to(pegin_addr, amt).await?;
        self.bitcoind.mine_blocks(11).await?;
        self.await_block_sync().await?;
        let (txout_proof, raw_tx) = tokio::try_join!(
            self.bitcoind.get_txout_proof(&txid),
            self.bitcoind.get_raw_transaction(&txid),
        )?;
        cmd!(
            self,
            "peg-in",
            "--txout-proof={txout_proof}",
            "--transaction={raw_tx}",
        )
        .run()
        .await?;
        cmd!(self, "fetch").run().await?;
        Ok(())
    }

    pub async fn pegin_gateway(&self, amt: u64, gw_cln: &Gatewayd) -> Result<()> {
        let fed_id = self.federation_id().await;
        let pegin_addr = cmd!(gw_cln, "address", "--federation-id={fed_id}")
            .out_json()
            .await?["address"]
            .as_str()
            .context("address must be a string")?
            .to_owned();
        let txid = self.bitcoind.send_to(pegin_addr, amt).await?;
        self.bitcoind.mine_blocks(11).await?;
        self.await_block_sync().await?;
        let (txout_proof, raw_tx) = tokio::try_join!(
            self.bitcoind.get_txout_proof(&txid),
            self.bitcoind.get_raw_transaction(&txid),
        )?;
        cmd!(
            gw_cln,
            "deposit",
            "--federation-id={fed_id}",
            "--txout-proof={txout_proof}",
            "--transaction={raw_tx}"
        )
        .run()
        .await?;
        cmd!(self, "fetch").run().await?;
        Ok(())
    }

    pub async fn federation_id(&self) -> String {
        self.client.config().0.federation_id.to_string()
    }

    pub async fn await_block_sync(&self) -> Result<()> {
        let wallet_cfg: WalletClientConfig = self
            .client
            .config()
            .0
            .get_module(LEGACY_HARDCODED_INSTANCE_ID_WALLET)?;
        let finality_delay = wallet_cfg.finality_delay;
        let btc_height = self.bitcoind.client().get_blockchain_info()?.blocks;
        let expected = btc_height - (finality_delay as u64);
        cmd!(self, "wait-block-height", expected).run().await?;
        Ok(())
    }

    pub async fn await_gateways_registered(&self) -> Result<()> {
        poll("gateways registered", || async {
            Ok(cmd!(self, "list-gateways").out_json().await?["num_gateways"].as_u64() == Some(2))
        })
        .await?;
        Ok(())
    }

    pub async fn await_all_peers(&self) -> Result<()> {
        cmd!(
            self,
            "api",
            "module_{LEGACY_HARDCODED_INSTANCE_ID_WALLET}_block_height"
        )
        .run()
        .await?;
        Ok(())
    }

    pub async fn use_gateway(&self, gw: &Gatewayd) -> Result<()> {
        let pub_key = match &gw.ln {
            Some(LightningNode::Cln(cln)) => cln.pub_key().await?,
            Some(LightningNode::Lnd(lnd)) => lnd.pub_key().await?,
            None => {
                return Err(anyhow::anyhow!(
                    "Gatewayd is disconnected from the Lightning Node"
                ))
            }
        };
        cmd!(self, "switch-gateway", pub_key).run().await?;
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
    ) -> Result<Self> {
        let cfg_dir = env::var("FM_DATA_DIR")?;
        let env_vars = fedimint_env(peer_id)?;
        let data_dir = env_vars
            .get("FM_FEDIMINT_DATA_DIR")
            .context("FM_FEDIMINT_DATA_DIR not found")?;
        fs::create_dir_all(data_dir).await?;

        // spawn fedimintd
        let cmd = cmd!("fedimintd", "--data-dir={cfg_dir}/server-{peer_id}").envs(env_vars);

        info!("fedimintd-{peer_id} started");
        let process = process_mgr
            .spawn_daemon(&format!("fedimintd-{peer_id}"), cmd)
            .await?;

        // TODO: wait for federation to start
        Ok(Self {
            _bitcoind: bitcoind,
            process,
        })
    }

    pub async fn kill(self) -> Result<()> {
        self.process.kill().await?;
        Ok(())
    }
}

pub async fn run_dkg(root_task_group: &TaskGroup, servers: usize) -> anyhow::Result<()> {
    async fn create_tls(id: usize, sender: Sender<String>) -> anyhow::Result<()> {
        // set env vars
        let server_name = format!("Server {id}!");
        let env_vars = fedimint_env(id)?;
        let p2p_url = env_vars.get("FM_P2P_URL").context("FM_P2P_URL not found")?;
        let api_url = env_vars.get("FM_API_URL").context("FM_API_URL not found")?;
        let out_dir = env_vars
            .get("FM_FEDIMINT_DATA_DIR")
            .context("FM_FEDIMINT_DATA_DIR not found")?;
        let cert_path = format!("{out_dir}/tls-cert");

        // create out-dir
        fs::create_dir(&out_dir).await?;

        info!("creating TLS certs created for started {server_name} in {out_dir}");
        cmd!(
            "distributedgen",
            "create-cert",
            "--p2p-url={p2p_url}",
            "--api-url={api_url}",
            "--out-dir={out_dir}",
            "--name={server_name}",
        )
        .envs(fedimint_env(id)?)
        .run()
        .await?;

        info!("TLS certs created for started {server_name}");

        // TODO: read TLS cert from disk and return if over channel
        let cert = fs::read_to_string(cert_path)
            .await
            .context("could not read TLS cert from disk")?;

        sender
            .send(cert)
            .await
            .context("failed to send cert over channel")?;

        Ok(())
    }

    async fn run_distributedgen(id: usize, certs: Vec<String>) -> anyhow::Result<()> {
        let certs = certs.join(",");
        let cfg_dir = env::var("FM_DATA_DIR")?;
        let server_name = format!("Server-{id}");

        let env_vars = fedimint_env(id)?;
        let bind_p2p = env_vars
            .get("FM_BIND_P2P")
            .expect("fedimint_env sets this key");
        let bind_api = env_vars
            .get("FM_BIND_API")
            .expect("fedimint_env sets this key");
        let out_dir = env_vars
            .get("FM_FEDIMINT_DATA_DIR")
            .expect("fedimint_env sets this key");

        info!("creating TLS certs created for started {server_name} in {out_dir}");
        cmd!(
            "distributedgen",
            "run",
            "--bind-p2p={bind_p2p}",
            "--bind-api={bind_api}",
            "--out-dir={out_dir}",
            "--certs={certs}",
        )
        .envs(fedimint_env(id)?)
        .run()
        .await
        .unwrap_or_else(|e| panic!("DKG failed for {server_name} {e:?}"));

        info!("DKG created for started {server_name}");

        // copy configs to config directory
        fs::rename(
            format!("{out_dir}/client-connect"),
            format!("{cfg_dir}/client-connect"),
        )
        .await?;
        fs::rename(
            format!("{out_dir}/client.json"),
            format!("{cfg_dir}/client.json"),
        )
        .await?;
        info!("copied client configs");

        Ok(())
    }

    let mut task_group = root_task_group.make_subgroup().await;

    // generate TLS certs
    let (sender, mut receiver): (Sender<String>, Receiver<String>) = mpsc::channel(1000);
    for id in 0..servers {
        let sender = sender.clone();
        task_group
            .spawn(
                format!("create TLS certs for server {id}"),
                move |_| async move {
                    info!("generating certs for server {}", id);
                    create_tls(id, sender).await.expect("create_tls failed");
                    info!("generating certs for server {}", id);
                },
            )
            .await;
    }
    task_group.join_all(None).await?;
    info!("Generated TLS certs");

    // collect TLS certs
    let mut certs = vec![];
    while certs.len() < servers {
        let cert = receiver
            .recv()
            .await
            .expect("couldn't receive cert over channel");
        certs.push(cert)
    }
    let certs_string = certs.join(",");
    info!("Collected TLS certs: {certs_string}");

    // generate keys
    let mut task_group = root_task_group.make_subgroup().await;
    for id in 0..servers {
        let certs = certs.clone();
        task_group
            .spawn(
                format!("create TLS certs for server {id}"),
                move |_| async move {
                    info!("generating keys for server {}", id);
                    run_distributedgen(id, certs)
                        .await
                        .expect("run_distributedgen failed");
                    info!("generating keys for server {}", id);
                },
            )
            .await;
    }

    task_group.join_all(None).await?;
    info!("DKG complete");

    Ok(())
}
