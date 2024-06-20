#![warn(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]

/// Module for creating `fedimintd` binary with custom modules
use bitcoin::Network;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::module::{
    ApiEndpoint, CommonModuleInit, CoreConsensusVersion, InputMeta, ModuleCommon,
    ModuleConsensusVersion, ModuleInit, PeerHandle, ServerModuleInit, ServerModuleInitArgs,
    SupportedModuleApiVersions, TransactionItemAmount, CORE_CONSENSUS_VERSION,
};
use fedimint_core::util::SafeUrl;
use fedimint_core::{plugin_types_trait_impl_common, Amount};
pub use fedimintd::*;

mod fedimintd;

pub mod envs;
use crate::envs::FM_PORT_ESPLORA_ENV;

pub const KIND: ModuleKind = ModuleKind::from_static_str("fedimintd");
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(2, 0);

pub struct FedimintdModuleTypes;

// plugin_types_trait_impl_common!(FedimintdModuleTypes);

#[derive(Debug)]
pub struct FedimintdInit;

impl CommonModuleInit for FedimintdInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = DummyClientConfig;

    fn decoder() -> Decoder {
        FedimintdModuleTypes::decoder_builder().build()
    }
}

// pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion =
// ModuleConsensusVersion::new(2, 0);

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
