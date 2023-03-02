use fedimint_core::config::{
    ClientModuleConfig, TypedClientModuleConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::Encodable;
use fedimint_core::PeerId;
use serde::{Deserialize, Serialize};

use crate::KIND;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DummyConfig {
    /// Contains all configuration that will be encrypted such as private key
    /// material
    pub private: DummyConfigPrivate,
    /// Contains all configuration that needs to be the same for every
    /// federation member
    pub consensus: DummyConfigConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize, Encodable)]
pub struct DummyConfigConsensus {
    pub something: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DummyConfigPrivate {
    pub something_private: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable)]
pub struct DummyClientConfig {
    pub something: u64,
}

impl TypedClientModuleConfig for DummyClientConfig {
    fn kind(&self) -> fedimint_core::core::ModuleKind {
        KIND
    }
}

impl TypedServerModuleConsensusConfig for DummyConfigConsensus {
    fn to_client_config(&self) -> ClientModuleConfig {
        ClientModuleConfig::from_typed(
            KIND,
            &(DummyClientConfig {
                something: self.something,
            }),
        )
        .expect("Serialization can't fail")
    }
}

impl TypedServerModuleConfig for DummyConfig {
    type Local = ();
    type Private = DummyConfigPrivate;
    type Consensus = DummyConfigConsensus;

    fn from_parts(_local: Self::Local, private: Self::Private, consensus: Self::Consensus) -> Self {
        Self { private, consensus }
    }

    fn to_parts(self) -> (ModuleKind, Self::Local, Self::Private, Self::Consensus) {
        (KIND, (), self.private, self.consensus)
    }

    fn validate_config(&self, _identity: &PeerId) -> anyhow::Result<()> {
        Ok(())
    }
}
