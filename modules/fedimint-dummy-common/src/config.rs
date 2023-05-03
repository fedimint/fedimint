use anyhow::bail;
use fedimint_core::config::{
    ClientModuleConfig, TypedClientModuleConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_core::{Amount, PeerId};
use serde::{Deserialize, Serialize};
use threshold_crypto::serde_impl::SerdeSecret;
use threshold_crypto::{PublicKeySet, SecretKeyShare};

use crate::{CONSENSUS_VERSION, KIND};

/// Contains all the configuration for the server
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DummyConfig {
    pub private: DummyConfigPrivate,
    pub consensus: DummyConfigConsensus,
}

/// Contains all the configuration for the client
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct DummyClientConfig {
    /// Accessible to clients
    pub tx_fee: Amount,
}

/// Will be the same for every federation member
#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct DummyConfigConsensus {
    /// Example federation threshold signing key
    pub public_key_set: PublicKeySet,
    /// Will be the same for all peers
    pub tx_fee: Amount,
}

/// Will be encrypted and not shared such as private key material
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DummyConfigPrivate {
    /// Example private key share for a single member
    pub private_key_share: SerdeSecret<SecretKeyShare>,
}

impl TypedServerModuleConsensusConfig for DummyConfigConsensus {
    /// Derives the client config from the consensus config
    fn to_client_config(&self) -> ClientModuleConfig {
        ClientModuleConfig::from_typed(
            KIND,
            CONSENSUS_VERSION,
            &(DummyClientConfig {
                tx_fee: self.tx_fee,
            }),
        )
        .expect("Serialization can't fail")
    }

    // TODO: Boilerplate-code
    fn kind(&self) -> ModuleKind {
        KIND
    }

    // TODO: Boilerplate-code
    fn version(&self) -> ModuleConsensusVersion {
        CONSENSUS_VERSION
    }
}

impl TypedServerModuleConfig for DummyConfig {
    type Local = ();
    type Private = DummyConfigPrivate;
    type Consensus = DummyConfigConsensus;

    // TODO: Boilerplate-code (remove local)
    fn from_parts(_: Self::Local, private: Self::Private, consensus: Self::Consensus) -> Self {
        Self { private, consensus }
    }

    // TODO: Boilerplate-code (remove local)
    fn to_parts(self) -> (ModuleKind, Self::Local, Self::Private, Self::Consensus) {
        (KIND, (), self.private, self.consensus)
    }

    /// Checks whether the config should be used
    fn validate_config(&self, identity: &PeerId) -> anyhow::Result<()> {
        let our_id = identity.to_usize();
        let our_share = self.consensus.public_key_set.public_key_share(our_id);

        // Check our private key matches our public key share
        if self.private.private_key_share.public_key_share() != our_share {
            bail!("Private key doesn't match public key share");
        }
        Ok(())
    }
}

// TODO: Boilerplate-code
impl TypedClientModuleConfig for DummyClientConfig {
    fn kind(&self) -> fedimint_core::core::ModuleKind {
        KIND
    }

    fn version(&self) -> ModuleConsensusVersion {
        CONSENSUS_VERSION
    }
}
