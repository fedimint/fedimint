use std::fmt;

use async_trait::async_trait;
use bitcoin_hashes::sha256;
use fedimint_core::config::ModuleGenParams;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::__reexports::serde_json;
use fedimint_core::module::{CommonModuleGen, ModuleCommon};
use fedimint_core::plugin_types_trait_impl_common;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::DummyClientConfig;
use crate::serde_json::Value;
pub mod config;
pub mod db;

const KIND: ModuleKind = ModuleKind::from_static_str("dummy");

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct DummyConsensusItem;

#[derive(Debug)]
pub struct DummyCommonGen;

#[async_trait]
impl CommonModuleGen for DummyCommonGen {
    const KIND: ModuleKind = KIND;

    fn decoder() -> Decoder {
        DummyModuleTypes::decoder_builder().build()
    }

    fn hash_client_module(config: Value) -> anyhow::Result<sha256::Hash> {
        Ok(serde_json::from_value::<DummyClientConfig>(config)?.consensus_hash())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyConfigGenParams {
    pub important_param: u64,
}

impl ModuleGenParams for DummyConfigGenParams {}

#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable, Default,
)]
pub struct DummyInput;

impl fmt::Display for DummyInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyInput")
    }
}

#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable, Default,
)]
pub struct DummyOutput;

impl fmt::Display for DummyOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyOutput")
    }
}
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct DummyOutputOutcome;

impl fmt::Display for DummyOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyOutputOutcome")
    }
}

impl fmt::Display for DummyConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyOutputConfirmation")
    }
}

pub struct DummyModuleTypes;

impl ModuleCommon for DummyModuleTypes {
    type Input = DummyInput;
    type Output = DummyOutput;
    type OutputOutcome = DummyOutputOutcome;
    type ConsensusItem = DummyConsensusItem;
}

plugin_types_trait_impl_common!(
    DummyInput,
    DummyOutput,
    DummyOutputOutcome,
    DummyConsensusItem
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error)]
pub enum DummyError {
    #[error("Something went wrong")]
    SomethingDummyWentWrong,
}
