use std::collections::BTreeMap;

use anyhow::{anyhow, Context};
use bitcoincore_rpc::bitcoin::Network;
use fedimint_aead::random_salt;
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_WALLET;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::util::write_new;
use fedimint_core::{Amount, PeerId};
use fedimint_server::config::io::{write_server_config, PLAINTEXT_PASSWORD, SALT_FILE};
use fedimint_server::config::ServerConfig;
use fedimint_testing::federation::local_config_gen_params;
use fedimint_wallet_client::config::WalletClientConfig;
use fedimintd::attach_default_module_gen_params;
use fedimintd::fedimintd::Fedimintd as FedimintBuilder;
use tokio::fs;

use super::*; // TODO: remove this

pub struct Federation {
    // client is only for internal use, use cli commands instead
    client: Arc<UserClient>,
    members: BTreeMap<usize, Fedimintd>,
    vars: BTreeMap<usize, vars::Fedimintd>,
    bitcoind: Bitcoind,
}

impl Federation {
    pub async fn new(
        process_mgr: &ProcessManager,
        bitcoind: Bitcoind,
        vars: BTreeMap<usize, vars::Fedimintd>,
    ) -> Result<Self> {
        let mut members = BTreeMap::new();
        for (peer, var) in &vars {
            members.insert(
                *peer,
                Fedimintd::new(process_mgr, bitcoind.clone(), *peer, var).await?,
            );
        }

        let workdir: PathBuf = env::var("FM_DATA_DIR")?.parse()?;
        let cfg_path = workdir.join("client.json");
        let cfg: UserClientConfig = load_from_file(&cfg_path)?;
        let decoders = module_decode_stubs();
        let db = Database::new(MemDatabase::new(), module_decode_stubs());
        let module_gens = ClientModuleGenRegistry::from(vec![
            DynClientModuleGen::from(WalletClientGen::default()),
            DynClientModuleGen::from(MintClientGen),
            DynClientModuleGen::from(LightningClientGen),
        ]);
        let client = UserClient::new(cfg, decoders, module_gens, db, Default::default()).await;
        Ok(Self {
            members,
            vars,
            bitcoind,
            client: Arc::new(client),
        })
    }

    pub async fn start_server(&mut self, process_mgr: &ProcessManager, peer: usize) -> Result<()> {
        if self.members.contains_key(&peer) {
            return Err(anyhow!("fedimintd-{} already running", peer));
        }
        self.members.insert(
            peer,
            Fedimintd::new(process_mgr, self.bitcoind.clone(), peer, &self.vars[&peer]).await?,
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

    pub async fn cmd(&self) -> Command {
        let cfg_dir = env::var("FM_DATA_DIR").unwrap();
        cmd!("fedimint-cli", "--data-dir={cfg_dir}")
    }

    pub async fn pegin(&self, amt: u64) -> Result<()> {
        let deposit = cmd!(self, "deposit-address").out_json().await?;
        let deposit_address = deposit["address"].as_str().unwrap();
        let deposit_operation_id = deposit["operation_id"].as_str().unwrap();

        self.bitcoind
            .send_to(deposit_address.to_owned(), amt)
            .await?;
        self.bitcoind.mine_blocks(100).await?;

        cmd!(self, "await-deposit", deposit_operation_id)
            .run()
            .await?;
        Ok(())
    }

    pub async fn pegin_gateway(&self, amt: u64, gw_cln: &Gatewayd) -> Result<()> {
        let fed_id = self.federation_id().await;
        let pegin_addr = cmd!(gw_cln, "address", "--federation-id={fed_id}")
            .out_json()
            .await?
            .as_str()
            .context("address must be a string")?
            .to_owned();
        self.bitcoind.send_to(pegin_addr, amt).await?;
        self.bitcoind.mine_blocks(21).await?;
        poll("gateway pegin", || async {
            let gateway_balance = cmd!(gw_cln, "balance", "--federation-id={fed_id}")
                .out_json()
                .await?
                .as_u64()
                .unwrap();

            Ok(gateway_balance == (amt * 1000))
        })
        .await?;
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
        cmd!(self, "dev", "wait-block-height", expected)
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
            "module_{LEGACY_HARDCODED_INSTANCE_ID_WALLET}_block_height"
        )
        .run()
        .await?;
        Ok(())
    }

    pub async fn use_gateway(&self, gw: &Gatewayd) -> Result<()> {
        let gateway_pub_key = gw.gateway_pub_key().await?;
        cmd!(self, "switch-gateway", gateway_pub_key.clone())
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

    pub async fn kill(self) -> Result<()> {
        self.process.kill().await?;
        Ok(())
    }
}

/// Base port for devimint
const BASE_PORT: u16 = 8173 + 10000;

pub async fn run_config_gen(
    process_mgr: &ProcessManager,
    servers: usize,
    write_password: bool,
) -> Result<BTreeMap<usize, vars::Fedimintd>> {
    // TODO: Use proper builder
    let mut fed = FedimintBuilder::new()?.with_default_modules();
    attach_default_module_gen_params(
        BitcoinRpcConfig::from_env_vars()?,
        &mut fed.server_gen_params,
        Amount::from_sats(100_000_000),
        Network::Regtest,
        10,
    );

    let peers: Vec<_> = (0..servers).map(|id| PeerId::from(id as u16)).collect();
    let params = local_config_gen_params(&peers, BASE_PORT, fed.server_gen_params.clone())?;
    let configs = ServerConfig::trusted_dealer_gen(&params, fed.server_gens.clone());
    let mut fedimintd_envs = BTreeMap::new();
    for (peer, cfg) in configs {
        let envs = vars::Fedimintd::init(&process_mgr.globals, &cfg).await?;
        let password = cfg.private.api_auth.0.clone();
        let data_dir = envs.FM_DATA_DIR.clone();
        fedimintd_envs.insert(peer.to_usize(), envs);
        write_new(data_dir.join(SALT_FILE), random_salt())?;
        write_server_config(&cfg, data_dir.clone(), &password, &fed.server_gens)?;
        if write_password {
            write_new(data_dir.join(PLAINTEXT_PASSWORD), &password)?;
        }
    }

    let out_dir = &fedimintd_envs[&0].FM_DATA_DIR;
    let cfg_dir = &process_mgr.globals.FM_DATA_DIR;
    let out_dir = utf8(out_dir);
    let cfg_dir = utf8(cfg_dir);
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

    info!("DKG complete");

    Ok(fedimintd_envs)
}
