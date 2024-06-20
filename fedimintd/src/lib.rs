#![warn(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]

use std::fmt;

/// Module for creating `fedimintd` binary with custom modules
use bitcoin::Network;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::module::{
    ApiEndpoint, CommonModuleInit, CoreConsensusVersion, InputMeta, ModuleCommon,
    ModuleConsensusVersion, ModuleInit, PeerHandle, ServerModuleInit, ServerModuleInitArgs,
    SupportedModuleApiVersions, TransactionItemAmount, CORE_CONSENSUS_VERSION,
};
use fedimint_core::util::SafeUrl;
use fedimint_core::{
    plugin_types_trait_impl_common, plugin_types_trait_impl_config, Amount, Amount,
};
pub use fedimintd::*;
use serde::{Deserialize, Serialize};

mod fedimintd;

pub mod envs;
use crate::envs::FM_PORT_ESPLORA_ENV;

pub const KIND: ModuleKind = ModuleKind::from_static_str("fedimintd");
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(2, 0);

#[derive(Debug)]
pub struct FedimintdInit;

impl ModuleInit for FedimintdInit {
    type Common = FedimintdCommonInit;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);
    // fn dump_database(
    //     &self,
    //     dbtx: &mut DatabaseTransaction<'_>,
    //     prefix_names: Vec<String>,
    // ) -> maybe_add_send!(
    //     impl Future<
    //         Output = Box<
    //             dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize +
    // Send>)> + '_,         >,
    //     >
    // ) {
    // }
}

#[derive(Debug)]
pub struct FedimintdCommonInit;
impl CommonModuleInit for FedimintdCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = FedimintdClientConfig;

    fn decoder() -> Decoder {
        FedimintdModuleTypes::decoder_builder().build()
    }
}

// -------------------------------------------------------

impl fmt::Display for FedimintdClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FedimintdClientConfig")
    }
}

// -------------------------------------------------------
// config.rs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FedimintdGenParams {
    pub local: FedimintdGenParamsLocal,
    pub consensus: FedimintdGenParamsConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FedimintdGenParamsLocal;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FedimintdGenParamsConsensus {
    pub tx_fee: Amount,
}

impl Default for FedimintdGenParams {
    fn default() -> Self {
        Self {
            local: FedimintdGenParamsLocal,
            consensus: FedimintdGenParamsConsensus {
                tx_fee: Amount::ZERO,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FedimintdConfig {
    pub local: FedimintdConfigLocal,
    pub private: FedimintdConfigPrivate,
    pub consensus: FedimintdConfigConsensus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct FedimintdClientConfig {
    /// Accessible to clients
    pub tx_fee: Amount,
}

/// Locally unencrypted config unique to each member
#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct FedimintdConfigLocal;

/// Will be the same for every federation member
#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct FedimintdConfigConsensus {
    /// Will be the same for all peers
    pub tx_fee: Amount,
}

/// Will be encrypted and not shared such as private key material
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FedimintdConfigPrivate;

plugin_types_trait_impl_config!(
    FedimintdCommonInit,
    FedimintdGenParams,
    FedimintdGenParamsLocal,
    FedimintdGenParamsConsensus,
    FedimintdConfig,
    FedimintdConfigLocal,
    FedimintdConfigPrivate,
    FedimintdConfigConsensus,
    FedimintdClientConfig
);
// -------------------------------------------------------

pub fn default_esplora_server(network: Network) -> BitcoinRpcConfig {
    let url = match network {
        Network::Bitcoin => SafeUrl::parse("https://blockstream.info/api/")
            .expect("Failed to parse default esplora server"),
        Network::Testnet => SafeUrl::parse("https://blockstream.info/testnet/api/")
            .expect("Failed to parse default esplora server"),
        Network::Regtest => SafeUrl::parse(&format!(
            "http://127.0.0.1:{}/",
            std::env::var(FM_PORT_ESPLORA_ENV).unwrap_or(String::from("50002"))
        ))
        .expect("Failed to parse default esplora server"),
        Network::Signet => SafeUrl::parse("https://mutinynet.com/api/")
            .expect("Failed to parse default esplora server"),
        _ => panic!("Failed to parse default esplora server"),
    };
    BitcoinRpcConfig {
        kind: "esplora".to_string(),
        url,
    }
}
