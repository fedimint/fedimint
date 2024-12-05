use std::fmt::Debug;
use std::sync::Arc;

use bitcoin::{Address, Txid};
use fedimint_core::util::SafeUrl;
use fedimint_core::{apply, async_trait_maybe_send, dyn_newtype_define};
use serde::{Deserialize, Serialize};

#[apply(async_trait_maybe_send!)]
pub trait IEsploraConnection: Debug {
    async fn get_address_utxo(
        &self,
        esplora: SafeUrl,
        address: Address,
    ) -> anyhow::Result<Vec<AddressUnspentTxOut>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressUnspentTxOut {
    pub txid: Txid,
    pub vout: u32,
    pub value: u64,
    pub status: AddressUnspentTxOutStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressUnspentTxOutStatus {
    pub block_height: Option<u64>,
}

dyn_newtype_define! {
    #[derive(Clone)]
    pub DynEsploraConnection(Arc<IEsploraConnection>)
}

#[derive(Debug, Clone)]
pub struct RealEsploraConnection;

#[apply(async_trait_maybe_send!)]
impl IEsploraConnection for RealEsploraConnection {
    async fn get_address_utxo(
        &self,
        esplora: SafeUrl,
        address: Address,
    ) -> anyhow::Result<Vec<AddressUnspentTxOut>> {
        Ok(reqwest::Client::new()
            .get(format!("{esplora}address/{address}/utxo"))
            .send()
            .await?
            .json::<Vec<AddressUnspentTxOut>>()
            .await?)
    }
}
