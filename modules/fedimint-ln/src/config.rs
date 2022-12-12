use anyhow::bail;
use fedimint_api::config::{ClientModuleConfig, TypedClientModuleConfig, TypedServerModuleConfig};
use fedimint_api::PeerId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningModuleConfig {
    pub threshold_pub_keys: threshold_crypto::PublicKeySet,
    // TODO: propose serde(with = "…") based protection upstream instead
    pub threshold_sec_key:
        threshold_crypto::serde_impl::SerdeSecret<threshold_crypto::SecretKeyShare>,
    pub threshold: usize,
    pub fee_consensus: FeeConsensus,
}

impl TypedClientModuleConfig for LightningModuleClientConfig {}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct LightningModuleClientConfig {
    pub threshold_pub_key: threshold_crypto::PublicKey,
    pub fee_consensus: FeeConsensus,
}

impl TypedServerModuleConfig for LightningModuleConfig {
    type Local = LightningModuleConfig;
    type Private = ();
    type Consensus = ();

    fn from_parts(
        local: Self::Local,
        _private: Self::Private,
        _consensus: Self::Consensus,
    ) -> Self {
        local
    }

    fn to_parts(self) -> (Self::Local, Self::Private, Self::Consensus) {
        (self, (), ())
    }

    fn to_client_config(&self) -> ClientModuleConfig {
        serde_json::to_value(&LightningModuleClientConfig {
            threshold_pub_key: self.threshold_pub_keys.public_key(),
            fee_consensus: self.fee_consensus.clone(),
        })
        .expect("Serialization can't fail")
        .into()
    }

    fn validate_config(&self, identity: &PeerId) -> anyhow::Result<()> {
        if self.threshold_sec_key.public_key_share()
            != self
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
