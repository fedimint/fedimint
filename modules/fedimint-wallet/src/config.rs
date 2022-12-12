use std::collections::BTreeMap;

use anyhow::bail;
use anyhow::format_err;
use bitcoin::Network;
use fedimint_api::config::TypedClientModuleConfig;
use fedimint_api::config::TypedServerModuleConfig;
use fedimint_api::config::{BitcoindRpcCfg, ClientModuleConfig};
use fedimint_api::module::__reexports::serde_json;
use fedimint_api::{Feerate, PeerId};
use miniscript::descriptor::Wsh;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};

use crate::keys::CompressedPublicKey;
use crate::PegInDescriptor;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    pub network: Network,
    pub peg_in_descriptor: PegInDescriptor,
    pub peer_peg_in_keys: BTreeMap<PeerId, CompressedPublicKey>,
    pub peg_in_key: secp256k1::SecretKey,
    pub finality_delay: u32,
    pub default_fee: Feerate,
    pub fee_consensus: FeeConsensus,
    #[serde(flatten)]
    pub btc_rpc: BitcoindRpcCfg,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct WalletClientConfig {
    /// The federations public peg-in-descriptor
    pub peg_in_descriptor: PegInDescriptor,
    /// The bitcoin network the client will use
    pub network: Network,
    /// Confirmations required for a peg in to be accepted by federation
    pub finality_delay: u32,
    pub fee_consensus: FeeConsensus,
}

impl TypedClientModuleConfig for WalletClientConfig {}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct FeeConsensus {
    pub peg_in_abs: fedimint_api::Amount,
    pub peg_out_abs: fedimint_api::Amount,
}

impl Default for FeeConsensus {
    fn default() -> Self {
        Self {
            peg_in_abs: fedimint_api::Amount::ZERO,
            peg_out_abs: fedimint_api::Amount::ZERO,
        }
    }
}

impl TypedServerModuleConfig for WalletConfig {
    type Local = WalletConfig;
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
        serde_json::to_value(&WalletClientConfig {
            peg_in_descriptor: self.peg_in_descriptor.clone(),
            network: self.network,
            fee_consensus: self.fee_consensus.clone(),
            finality_delay: self.finality_delay,
        })
        .expect("Serialization can't fail")
        .into()
    }

    fn validate_config(&self, identity: &PeerId) -> anyhow::Result<()> {
        let pubkey = secp256k1::PublicKey::from_secret_key_global(&self.peg_in_key);

        if self
            .peer_peg_in_keys
            .get(identity)
            .ok_or_else(|| format_err!("Secret key doesn't match any public key"))?
            != &CompressedPublicKey::new(pubkey)
        {
            bail!(" Bitcoin wallet private key doesn't match multisig pubkey");
        }

        Ok(())
    }
}

impl WalletConfig {
    pub fn new(
        pubkeys: BTreeMap<PeerId, CompressedPublicKey>,
        sk: SecretKey,
        threshold: usize,
        btc_rpc: BitcoindRpcCfg,
        network: bitcoin::network::constants::Network,
        finality_delay: u32,
    ) -> Self {
        let peg_in_descriptor = PegInDescriptor::Wsh(
            Wsh::new_sortedmulti(threshold, pubkeys.iter().map(|(_, pk)| *pk).collect()).unwrap(),
        );

        Self {
            network,
            peg_in_descriptor,
            peer_peg_in_keys: pubkeys,
            peg_in_key: sk,
            default_fee: Feerate { sats_per_kvb: 1000 },
            finality_delay,
            fee_consensus: FeeConsensus::default(),
            btc_rpc,
        }
    }
}

impl WalletClientConfig {
    pub fn new(
        peg_in_descriptor: PegInDescriptor,
        network: bitcoin::network::constants::Network,
        finality_delay: u32,
    ) -> Self {
        Self {
            peg_in_descriptor,
            network,
            finality_delay,
            fee_consensus: Default::default(),
        }
    }
}
