use std::collections::BTreeMap;

use anyhow::{bail, format_err};
use bitcoin::Network;
use fedimint_core::config::{
    ClientModuleConfig, TypedClientModuleConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Feerate, PeerId};
use miniscript::descriptor::Wsh;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};

use crate::keys::CompressedPublicKey;
use crate::PegInDescriptor;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    /// Contains all configuration that is locally configurable and not secret
    pub local: WalletConfigLocal,
    /// Contains all configuration that will be encrypted such as private key
    /// material
    pub private: WalletConfigPrivate,
    /// Contains all configuration that needs to be the same for every server
    pub consensus: WalletConfigConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfigLocal;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfigPrivate {
    /// Secret key for signing bitcoin multisig transactions
    pub peg_in_key: SecretKey,
}

#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct WalletConfigConsensus {
    /// Bitcoin network (e.g. testnet, bitcoin)
    pub network: Network,
    /// The federations public peg-in-descriptor
    pub peg_in_descriptor: PegInDescriptor,
    /// The public keys for the bitcoin multisig
    pub peer_peg_in_keys: BTreeMap<PeerId, CompressedPublicKey>,
    /// How many bitcoin blocks to wait before considering a transaction
    /// confirmed
    pub finality_delay: u32,
    /// If we cannot determine the feerate from our bitcoin node, default to
    /// this
    pub default_fee: Feerate,
    /// Fees for bitcoin transactions
    pub fee_consensus: FeeConsensus,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct WalletClientConfig {
    /// The federations public peg-in-descriptor
    pub peg_in_descriptor: PegInDescriptor,
    /// The bitcoin network the client will use
    pub network: Network,
    /// Confirmations required for a peg in to be accepted by federation
    pub finality_delay: u32,
    pub fee_consensus: FeeConsensus,
}

impl TypedClientModuleConfig for WalletClientConfig {
    fn kind(&self) -> ModuleKind {
        crate::KIND
    }

    fn version(&self) -> fedimint_core::module::ModuleConsensusVersion {
        crate::CONSENSUS_VERSION
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FeeConsensus {
    pub peg_in_abs: fedimint_core::Amount,
    pub peg_out_abs: fedimint_core::Amount,
}

impl Default for FeeConsensus {
    fn default() -> Self {
        Self {
            peg_in_abs: fedimint_core::Amount::ZERO,
            peg_out_abs: fedimint_core::Amount::ZERO,
        }
    }
}

impl TypedServerModuleConsensusConfig for WalletConfigConsensus {
    fn to_client_config(&self) -> ClientModuleConfig {
        ClientModuleConfig::from_typed(
            crate::KIND,
            crate::CONSENSUS_VERSION,
            &WalletClientConfig {
                peg_in_descriptor: self.peg_in_descriptor.clone(),
                network: self.network,
                fee_consensus: self.fee_consensus.clone(),
                finality_delay: self.finality_delay,
            },
        )
        .expect("Serialization can't fail")
    }

    fn kind(&self) -> ModuleKind {
        crate::KIND
    }

    fn version(&self) -> fedimint_core::module::ModuleConsensusVersion {
        crate::CONSENSUS_VERSION
    }
}

impl TypedServerModuleConfig for WalletConfig {
    type Local = WalletConfigLocal;
    type Private = WalletConfigPrivate;
    type Consensus = WalletConfigConsensus;

    fn from_parts(local: Self::Local, private: Self::Private, consensus: Self::Consensus) -> Self {
        Self {
            local,
            private,
            consensus,
        }
    }

    fn to_parts(self) -> (ModuleKind, Self::Local, Self::Private, Self::Consensus) {
        (crate::KIND, self.local, self.private, self.consensus)
    }

    fn validate_config(&self, identity: &PeerId) -> anyhow::Result<()> {
        let pubkey = secp256k1::PublicKey::from_secret_key_global(&self.private.peg_in_key);

        if self
            .consensus
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
        network: Network,
        finality_delay: u32,
    ) -> Self {
        let peg_in_descriptor = PegInDescriptor::Wsh(
            Wsh::new_sortedmulti(threshold, pubkeys.values().copied().collect()).unwrap(),
        );

        Self {
            local: WalletConfigLocal,
            private: WalletConfigPrivate { peg_in_key: sk },
            consensus: WalletConfigConsensus {
                network,
                peg_in_descriptor,
                peer_peg_in_keys: pubkeys,
                finality_delay,
                default_fee: Feerate { sats_per_kvb: 1000 },
                fee_consensus: Default::default(),
            },
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
