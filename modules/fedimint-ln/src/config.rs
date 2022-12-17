use anyhow::bail;
use fedimint_api::config::{ClientModuleConfig, TypedClientModuleConfig, TypedServerModuleConfig};
use fedimint_api::PeerId;
use serde::{Deserialize, Serialize};
use threshold_crypto::serde_impl::SerdeSecret;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningModuleConfig {
    /// Contains all configuration that will be encrypted such as private key material
    pub private: LightningConfigPrivate,
    /// Contains all configuration that needs to be the same for every server
    pub consensus: LightningConfigConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningConfigConsensus {
    /// The threshold public keys for encrypting the LN preimage
    pub threshold_pub_keys: threshold_crypto::PublicKeySet,
    /// The number of decryption shares required
    pub threshold: usize,
    /// Fees charged for LN transactions
    pub fee_consensus: FeeConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningConfigPrivate {
    // TODO: propose serde(with = "…") based protection upstream instead
    /// Our secret key for decrypting preimages
    pub threshold_sec_key: SerdeSecret<threshold_crypto::SecretKeyShare>,
}

impl TypedClientModuleConfig for LightningModuleClientConfig {}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct LightningModuleClientConfig {
    pub threshold_pub_key: threshold_crypto::PublicKey,
    pub fee_consensus: FeeConsensus,
}

impl TypedServerModuleConfig for LightningModuleConfig {
    type Local = ();
    type Private = LightningConfigPrivate;
    type Consensus = LightningConfigConsensus;

    fn from_parts(_local: Self::Local, private: Self::Private, consensus: Self::Consensus) -> Self {
        Self { private, consensus }
    }

    fn to_parts(self) -> (Self::Local, Self::Private, Self::Consensus) {
        ((), self.private, self.consensus)
    }

    fn to_client_config(&self) -> ClientModuleConfig {
        serde_json::to_value(&LightningModuleClientConfig {
            threshold_pub_key: self.consensus.threshold_pub_keys.public_key(),
            fee_consensus: self.consensus.fee_consensus.clone(),
        })
        .expect("Serialization can't fail")
        .into()
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

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct FeeConsensus {
    pub contract_input: fedimint_api::Amount,
    pub contract_output: fedimint_api::Amount,
}

impl Default for FeeConsensus {
    fn default() -> Self {
        Self {
            contract_input: fedimint_api::Amount::ZERO,
            contract_output: fedimint_api::Amount::ZERO,
        }
    }
}
