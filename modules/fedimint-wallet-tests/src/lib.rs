use std::collections::BTreeMap;
use std::ffi::OsString;

use fedimint_bitcoind::DynBitcoindRpc;
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
use fedimint_core::{apply, async_trait_maybe_send, PeerId};
use fedimint_testing::fixtures::Fixtures;
use fedimint_wallet_client::WalletCommonGen;
use fedimint_wallet_server::{Wallet, WalletGen};

#[derive(Debug, Clone)]
/// Used to create a wallet module with a mock bitcoind
pub struct FakeWalletGen {
    inner: WalletGen,
    bitcoin_rpc: DynBitcoindRpc,
}

impl FakeWalletGen {
    pub fn new(fixtures: &Fixtures) -> Self {
        Self::with_rpc(fixtures.bitcoin_rpc())
    }

    pub fn with_rpc(bitcoin_rpc: DynBitcoindRpc) -> Self {
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
    ) -> anyhow::Result<DynServerModule> {
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

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
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
