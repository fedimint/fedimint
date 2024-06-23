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
use config::FedimintdClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::db::DatabaseVersion;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion, ModuleInit};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::util::SafeUrl;
use fedimint_core::{plugin_types_trait_impl_common, Amount};
pub use fedimintd::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod fedimintd;

pub mod config;
pub mod envs;

use crate::envs::FM_PORT_ESPLORA_ENV;

pub const KIND: ModuleKind = ModuleKind::from_static_str("fedimintd");
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(2, 0);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FedimintdConsensusItem;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct FedimintdInput {
    pub amount: Amount,
    pub account: PublicKey,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct FedimintdOutput {
    pub amount: Amount,
    pub account: PublicKey,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct FedimintdOutputOutcome(pub Amount, pub PublicKey);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum FedimintdInputError {
    #[error("Not enough funds")]
    NotEnoughFunds,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum FedimintdOutputError {}

pub struct FedimintdModuleTypes;

plugin_types_trait_impl_common!(
    FedimintdModuleTypes,
    FedimintdClientConfig,
    FedimintdInput,
    FedimintdOutput,
    FedimintdOutputOutcome,
    FedimintdConsensusItem,
    FedimintdInputError,
    FedimintdOutputError
);

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

impl fmt::Display for FedimintdClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FedimintdClientConfig")
    }
}

impl fmt::Display for FedimintdInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FedimintdInput")
    }
}

impl fmt::Display for FedimintdOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FedimintdOutput")
    }
}

impl fmt::Display for FedimintdOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FedimintdOutputOutcome")
    }
}

impl fmt::Display for FedimintdConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FedimintdConsensusItem")
    }
}

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
