use std::collections::{BTreeMap, HashMap, VecDeque};
use std::ffi::OsString;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{Block, BlockHash, BlockHeader, Network, Transaction};
use fedimint_bitcoind::{DynBitcoindRpc, IBitcoindRpc, Result};
use fedimint_core::config::{
    ClientModuleConfig, ConfigGenModuleParams, DkgResult, ServerModuleConfig,
    ServerModuleConsensusConfig,
};
use fedimint_core::db::{Database, DatabaseVersion, ModuleDatabaseTransaction};
use fedimint_core::module::{
    CoreConsensusVersion, ExtendsCommonModuleGen, ModuleConsensusVersion, PeerHandle,
    ServerModuleGen,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::task::TaskGroup;
use fedimint_core::{apply, async_trait_maybe_send, Feerate, PeerId};
use fedimint_wallet_client::WalletCommonGen;
use fedimint_wallet_server::{Wallet, WalletGen};

#[derive(Debug, Clone)]
/// Used to create a wallet module with a mock bitcoind
pub struct FakeWalletGen {
    inner: WalletGen,
    bitcoin_rpc: DynBitcoindRpc,
}

impl FakeWalletGen {
    pub fn new(bitcoin_rpc: DynBitcoindRpc) -> Self {
        Self {
            inner: WalletGen,
            bitcoin_rpc,
        }
    }
}

impl ExtendsCommonModuleGen for FakeWalletGen {
    type Common = WalletCommonGen;
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleGen for FakeWalletGen {
    const DATABASE_VERSION: DatabaseVersion = WalletGen::DATABASE_VERSION;

    fn versions(&self, core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        self.inner.versions(core)
    }

    async fn init(
        &self,
        cfg: ServerModuleConfig,
        db: Database,
        _env: &BTreeMap<OsString, OsString>,
        task_group: &mut TaskGroup,
    ) -> Result<DynServerModule> {
        Ok(Wallet::new_with_bitcoind(
            cfg.to_typed().expect("config is correct type"),
            db,
            self.bitcoin_rpc.clone(),
            task_group,
        )
        .await?
        .into())
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        self.inner.trusted_dealer_gen(peers, params)
    }

    async fn distributed_gen(
        &self,
        peer: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig> {
        self.inner.distributed_gen(peer, params).await
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> Result<()> {
        self.inner.validate_config(identity, config)
    }

    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<ClientModuleConfig> {
        self.inner.get_client_config(config)
    }

    async fn dump_database(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        self.inner.dump_database(dbtx, prefix_names).await
    }
}

#[derive(Debug, Default)]
pub struct FakeBitcoindRpcState {
    fee_rate: Option<Feerate>,
    block_height: u64,
    transactions: VecDeque<Transaction>,
    tx_in_blocks: HashMap<BlockHash, Vec<Transaction>>,
}

#[derive(Debug, Default, Clone)]
pub struct FakeBitcoindRpc {
    state: Arc<Mutex<FakeBitcoindRpcState>>,
}

pub struct FakeBitcoindRpcController {
    pub state: Arc<Mutex<FakeBitcoindRpcState>>,
}

#[async_trait]
impl IBitcoindRpc for FakeBitcoindRpc {
    async fn get_network(&self) -> Result<Network> {
        Ok(bitcoin::Network::Regtest)
    }

    async fn get_block_height(&self) -> Result<u64> {
        Ok(self.state.lock().unwrap().block_height)
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        Ok(height_hash(height))
    }

    async fn get_block(&self, hash: &BlockHash) -> Result<Block> {
        let txdata = self
            .state
            .lock()
            .unwrap()
            .tx_in_blocks
            .get(hash)
            .cloned()
            .unwrap_or_default();
        Ok(Block {
            header: BlockHeader {
                version: 0,
                prev_blockhash: sha256d::Hash::hash(b"").into(),
                merkle_root: sha256d::Hash::hash(b"").into(),
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txdata,
        })
    }

    async fn get_fee_rate(&self, _confirmation_target: u16) -> Result<Option<Feerate>> {
        Ok(self.state.lock().unwrap().fee_rate)
    }

    async fn submit_transaction(&self, transaction: Transaction) {
        self.state
            .lock()
            .unwrap()
            .transactions
            .push_back(transaction);
    }
}

impl FakeBitcoindRpc {
    pub fn new() -> FakeBitcoindRpc {
        FakeBitcoindRpc::default()
    }

    pub fn controller(&self) -> FakeBitcoindRpcController {
        FakeBitcoindRpcController {
            state: self.state.clone(),
        }
    }
}

impl FakeBitcoindRpcController {
    pub async fn set_fee_rate(&self, fee_rate: Option<Feerate>) {
        self.state.lock().unwrap().fee_rate = fee_rate;
    }

    pub async fn set_block_height(&self, block_height: u64) {
        self.state.lock().unwrap().block_height = block_height
    }

    pub async fn is_btc_sent_to(
        &self,
        amount: bitcoin::Amount,
        recipient: bitcoin::Address,
    ) -> bool {
        self.state
            .lock()
            .unwrap()
            .transactions
            .iter()
            .flat_map(|tx| tx.output.iter())
            .any(|output| {
                output.value == amount.to_sat() && output.script_pubkey == recipient.script_pubkey()
            })
    }

    pub async fn add_pending_tx_to_block(&self, block: u64) {
        let block_hash = height_hash(block);
        let mut state = self.state.lock().unwrap();
        #[allow(clippy::needless_collect)]
        let txns = state.transactions.drain(..).collect::<Vec<_>>();
        state
            .tx_in_blocks
            .entry(block_hash)
            .or_default()
            .extend(txns.into_iter());
    }
}

fn height_hash(height: u64) -> BlockHash {
    let mut bytes = [0u8; 32];
    // Exceptionally use little endian to match bitcoin consensus encoding
    bytes[..8].copy_from_slice(&height.to_le_bytes()[..]);
    BlockHash::from_inner(bytes)
}
