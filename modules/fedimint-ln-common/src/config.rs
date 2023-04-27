use anyhow::bail;
use fedimint_core::config::{
    ClientModuleConfig, TypedClientModuleConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::PeerId;
use serde::{Deserialize, Serialize};
use threshold_crypto::serde_impl::SerdeSecret;

use crate::{CONSENSUS_VERSION, KIND};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningConfig {
    /// Contains all configuration that will be encrypted such as private key
    /// material
    pub private: LightningConfigPrivate,
    /// Contains all configuration that needs to be the same for every server
    pub consensus: LightningConfigConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct LightningConfigConsensus {
    /// The threshold public keys for encrypting the LN preimage
    pub threshold_pub_keys: threshold_crypto::PublicKeySet,
    /// Fees charged for LN transactions
    pub fee_consensus: FeeConsensus,
}

impl LightningConfigConsensus {
    /// The number of decryption shares required
    pub fn threshold(&self) -> usize {
        self.threshold_pub_keys.threshold() + 1
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningConfigPrivate {
    // TODO: propose serde(with = "…") based protection upstream instead
    /// Our secret key for decrypting preimages
    pub threshold_sec_key: SerdeSecret<threshold_crypto::SecretKeyShare>,
}

impl TypedClientModuleConfig for LightningClientConfig {
    fn kind(&self) -> ModuleKind {
        KIND
    }

    fn version(&self) -> fedimint_core::module::ModuleConsensusVersion {
        CONSENSUS_VERSION
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct LightningClientConfig {
    pub threshold_pub_key: threshold_crypto::PublicKey,
    pub fee_consensus: FeeConsensus,
}

impl TypedServerModuleConsensusConfig for LightningConfigConsensus {
    fn to_client_config(&self) -> ClientModuleConfig {
        ClientModuleConfig::from_typed(
            KIND,
            CONSENSUS_VERSION,
            &LightningClientConfig {
                threshold_pub_key: self.threshold_pub_keys.public_key(),
                fee_consensus: self.fee_consensus.clone(),
            },
        )
        .expect("Serialization can't fail")
    }

    fn kind(&self) -> ModuleKind {
        KIND
    }

    fn version(&self) -> fedimint_core::module::ModuleConsensusVersion {
        CONSENSUS_VERSION
    }
}

impl TypedServerModuleConfig for LightningConfig {
    type Local = ();
    type Private = LightningConfigPrivate;
    type Consensus = LightningConfigConsensus;

    fn from_parts(_local: Self::Local, private: Self::Private, consensus: Self::Consensus) -> Self {
        Self { private, consensus }
    }

    fn to_parts(self) -> (ModuleKind, Self::Local, Self::Private, Self::Consensus) {
        (KIND, (), self.private, self.consensus)
    }

    fn validate_config(&self, identity: &PeerId) -> anyhow::Result<()> {
        if self.private.threshold_sec_key.public_key_share()
            != self
                .consensus
                .threshold_pub_keys
                .public_key_share(identity.to_usize())
        {
            bail!("Lightning private key doesn't match pubkey share");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FeeConsensus {
    pub contract_input: fedimint_core::Amount,
    pub contract_output: fedimint_core::Amount,
}

impl Default for FeeConsensus {
    fn default() -> Self {
        Self {
            contract_input: fedimint_core::Amount::ZERO,
            contract_output: fedimint_core::Amount::ZERO,
        }
    }
}
