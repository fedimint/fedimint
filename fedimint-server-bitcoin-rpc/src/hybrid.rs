mod backend;
#[cfg(test)]
mod tests;

use std::sync::OnceLock;

use anyhow::{Result, anyhow, ensure};
use bitcoin::{BlockHash, Transaction};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::util::{FmtCompactAnyhow as _, SafeUrl};
use fedimint_core::{ChainId, Feerate};
use fedimint_logging::LOG_SERVER;
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;
use tracing::{info, warn};

use self::backend::{Backend, Status};
use crate::bitcoind::BitcoindClient;
use crate::esplora::EsploraClient;

/// A bitcoind primary and trusted Esplora fallback on one chain.
///
/// Esplora is trusted for chain selection, including startup without bitcoind.
/// Chain equality checks catch misconfiguration; they are not SPV verification.
/// Reads prefer a non-IBD primary unless Esplora reports a higher tip.
/// Broadcast remains primary-first, using Esplora only after a primary error.
/// Configuration and URL accessors describe the primary only.
#[derive(Debug)]
pub struct BitcoindClientWithFallback {
    /// Primary full-node RPC and remembered health/identity.
    bitcoind_client: Backend,
    /// Trusted fallback RPC and remembered health/identity.
    esplora_client: Backend,
    /// Process identity learned from available trusted endpoints at startup.
    chain_id: OnceLock<ChainId>,
}

impl BitcoindClientWithFallback {
    /// Construct a hybrid backend using two explicitly trusted endpoints.
    pub fn new(
        username: String,
        password: String,
        bitcoind_url: &SafeUrl,
        esplora_url: &SafeUrl,
    ) -> Result<Self> {
        info!(
            target: LOG_SERVER,
            %bitcoind_url,
            %esplora_url,
            "Initializing bitcoin bitcoind backend with trusted esplora fallback"
        );
        Ok(Self {
            bitcoind_client: Backend::new(
                "bitcoind",
                BitcoindClient::new(username, password, bitcoind_url)?.into_dyn(),
            ),
            esplora_client: Backend::new("esplora", EsploraClient::new(esplora_url)?.into_dyn()),
            chain_id: OnceLock::new(),
        })
    }

    /// Establish one identity, using trusted Esplora if Core is unavailable.
    fn establish_identity(
        &self,
        primary: &Result<Status>,
        fallback: &Result<Status>,
    ) -> Result<ChainId> {
        if let Some(id) = self.chain_id.get() {
            return Ok(*id);
        }
        let id = match (primary, fallback) {
            (Ok(primary), Ok(fallback)) => {
                if primary.chain_id != fallback.chain_id {
                    let error = anyhow!("Bitcoind and Esplora chain identities differ");
                    self.bitcoind_client.failed(&error);
                    self.esplora_client.failed(&error);
                    return Err(error);
                }
                primary.chain_id
            }
            (Ok(status), Err(_)) | (Err(_), Ok(status)) => status.chain_id,
            (Err(primary), Err(fallback)) => {
                return Err(anyhow!(
                    "Cannot establish Bitcoin chain identity: bitcoind: {primary:#}; esplora: {fallback:#}"
                ));
            }
        };
        let _ = self.chain_id.set(id);
        Ok(*self.chain_id.get().expect("chain identity was established"))
    }

    /// Prefer the primary at equal tips, otherwise use the fresher ready
    /// source.
    async fn read_backends(&self) -> Result<Vec<&Backend>> {
        let (primary, fallback) =
            tokio::join!(self.bitcoind_client.status(), self.esplora_client.status(),);
        let expected = self.establish_identity(&primary, &fallback)?;
        let usable = |backend: &Backend, result: Result<Status>| -> Result<u64> {
            let status = result?;
            if status.chain_id != expected {
                let error = anyhow!("Bitcoin backend chain identity mismatch");
                backend.failed(&error);
                return Err(error);
            }
            ensure!(!status.ibd, "Bitcoin backend is in initial block download");
            Ok(status.count)
        };
        match (
            usable(&self.bitcoind_client, primary),
            usable(&self.esplora_client, fallback),
        ) {
            (Ok(primary), Ok(fallback)) if primary < fallback => {
                // Do not fall back to the known-stale primary if Esplora fails.
                Ok(vec![&self.esplora_client])
            }
            (Ok(_), Ok(_)) => Ok(vec![&self.bitcoind_client, &self.esplora_client]),
            (Ok(_), Err(error)) => {
                warn!(target: LOG_SERVER, error = %error.fmt_compact_anyhow(), "Esplora is not eligible for reads");
                Ok(vec![&self.bitcoind_client])
            }
            (Err(error), Ok(_)) => {
                warn!(target: LOG_SERVER, error = %error.fmt_compact_anyhow(), "Bitcoind is not eligible for reads");
                Ok(vec![&self.esplora_client])
            }
            (Err(primary), Err(fallback)) => Err(anyhow!(
                "No usable Bitcoin backend: bitcoind: {primary:#}; esplora: {fallback:#}"
            )),
        }
    }

    async fn broadcast(&self, backend: &Backend, transaction: Transaction) -> Result<()> {
        let expected = self.get_chain_id().await?;
        backend.check_identity(expected).await?;
        backend.rpc.submit_transaction(transaction).await
    }
}

/// Keep every read on the same eligibility and error-handling path.
macro_rules! read_rpc {
    ($self:ident, $method:ident $(, $arg:expr)*) => {{
        let mut errors = Vec::new();
        for backend in $self.read_backends().await? {
            let expected = *$self.chain_id.get().expect("read selection established identity");
            let result = async {
                // Usually a local cache read. Revalidate if another request
                // observed failure after this call selected the backend.
                backend.check_identity(expected).await?;
                backend.rpc.$method($($arg),*).await
            }.await;
            match result {
                Ok(value) => return Ok(value),
                Err(error) => {
                    backend.failed(&error);
                    warn!(
                        target: LOG_SERVER,
                        backend = backend.name,
                        method = stringify!($method),
                        error = %error.fmt_compact_anyhow(),
                        "Bitcoin read failed; trying any other eligible backend"
                    );
                    errors.push(format!("{}: {error:#}", backend.name));
                }
            }
        }
        Err(anyhow!("Bitcoin read failed: {}", errors.join("; ")))
    }};
}

#[async_trait::async_trait]
impl IServerBitcoinRpc for BitcoindClientWithFallback {
    fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig {
        self.bitcoind_client.rpc.get_bitcoin_rpc_config()
    }

    fn get_url(&self) -> SafeUrl {
        self.bitcoind_client.rpc.get_url()
    }

    async fn get_block_count(&self) -> Result<u64> {
        read_rpc!(self, get_block_count)
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        read_rpc!(self, get_block_hash, height)
    }

    async fn get_block(&self, block_hash: &BlockHash) -> Result<bitcoin::Block> {
        read_rpc!(self, get_block, block_hash)
    }

    async fn get_feerate(&self) -> Result<Option<Feerate>> {
        read_rpc!(self, get_feerate)
    }

    async fn submit_transaction(&self, transaction: Transaction) -> Result<()> {
        match self
            .broadcast(&self.bitcoind_client, transaction.clone())
            .await
        {
            Ok(()) => Ok(()),
            Err(primary) => {
                self.bitcoind_client.failed(&primary);
                warn!(target: LOG_SERVER, error = %primary.fmt_compact_anyhow(), "Bitcoind broadcast failed; trying Esplora");
                self.broadcast(&self.esplora_client, transaction)
                    .await
                    .map_err(|fallback| {
                        self.esplora_client.failed(&fallback);
                        anyhow!(
                            "Bitcoin broadcast failed: bitcoind: {primary:#}; esplora: {fallback:#}"
                        )
                    })
            }
        }
    }

    async fn get_sync_progress(&self) -> Result<Option<f64>> {
        // Eligibility already excludes IBD. Esplora has no progress estimate.
        self.read_backends().await?;
        Ok(None)
    }

    async fn get_chain_id(&self) -> Result<ChainId> {
        if let Some(id) = self.chain_id.get() {
            return Ok(*id);
        }
        let (primary, fallback) =
            tokio::join!(self.bitcoind_client.status(), self.esplora_client.status(),);
        // Identity is independent of read readiness: an IBD node can still
        // identify its chain and attempt transaction broadcast.
        self.establish_identity(&primary, &fallback)
    }
}
