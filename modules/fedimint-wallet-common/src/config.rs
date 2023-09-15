use std::collections::BTreeMap;

use bitcoin::Network;
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::__reexports::serde_json;
use fedimint_core::util::SafeUrl;
use fedimint_core::{plugin_types_trait_impl_config, Feerate, PeerId};
use miniscript::descriptor::Wsh;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};

use crate::keys::CompressedPublicKey;
use crate::{PegInDescriptor, WalletCommonGen};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletGenParams {
    pub local: WalletGenParamsLocal,
    pub consensus: WalletGenParamsConsensus,
}

impl WalletGenParams {
    pub fn regtest(bitcoin_rpc: BitcoinRpcConfig) -> WalletGenParams {
        WalletGenParams {
            local: WalletGenParamsLocal { bitcoin_rpc },
            consensus: WalletGenParamsConsensus {
                network: Network::Regtest,
                finality_delay: 10,
                client_default_bitcoin_rpc: BitcoinRpcConfig {
                    kind: "esplora".to_string(),
                    url: SafeUrl::parse("http://127.0.0.1:50002/")
                        .expect("Failed to parse default esplora server"),
                },
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletGenParamsLocal {
    pub bitcoin_rpc: BitcoinRpcConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletGenParamsConsensus {
    pub network: Network,
    pub finality_delay: u32,
    /// See [`WalletConfigConsensus::client_default_bitcoin_rpc`].
    pub client_default_bitcoin_rpc: BitcoinRpcConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    pub local: WalletConfigLocal,
    pub private: WalletConfigPrivate,
    pub consensus: WalletConfigConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct WalletConfigLocal {
    /// Configures which bitcoin RPC to use
    pub bitcoin_rpc: BitcoinRpcConfig,
    /// Our own peer_id
    pub our_peer_id: PeerId,
}

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
    /// Points to a Bitcoin API that the client can use to interact with the
    /// Bitcoin blockchain (mostly for deposits). *Eventually the backend should
    /// become configurable locally and this should merely be a suggested
    /// default by the federation.*
    ///
    /// **This is only used by the client, the RPC used by the server is defined
    /// in [`WalletConfigLocal`].**
    pub client_default_bitcoin_rpc: BitcoinRpcConfig,
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
    /// Points to a Bitcoin API that the client can use to interact with the
    /// Bitcoin blockchain (mostly for deposits). *Eventually the backend should
    /// become configurable locally and this should merely be a suggested
    /// default by the federation.*
    pub default_bitcoin_rpc: BitcoinRpcConfig,
}

impl std::fmt::Display for WalletClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WalletClientConfig {}",
            serde_json::to_string(self).map_err(|_e| std::fmt::Error)?
        )
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

impl WalletConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pubkeys: BTreeMap<PeerId, CompressedPublicKey>,
        sk: SecretKey,
        our_peer_id: PeerId,
        threshold: usize,
        network: Network,
        finality_delay: u32,
        bitcoin_rpc: BitcoinRpcConfig,
        client_default_bitcoin_rpc: BitcoinRpcConfig,
    ) -> Self {
        let peg_in_descriptor = PegInDescriptor::Wsh(
            Wsh::new_sortedmulti(threshold, pubkeys.values().copied().collect()).unwrap(),
        );

        Self {
            local: WalletConfigLocal {
                bitcoin_rpc,
                our_peer_id,
            },
            private: WalletConfigPrivate { peg_in_key: sk },
            consensus: WalletConfigConsensus {
                network,
                peg_in_descriptor,
                peer_peg_in_keys: pubkeys,
                finality_delay,
                default_fee: Feerate { sats_per_kvb: 1000 },
                fee_consensus: Default::default(),
                client_default_bitcoin_rpc,
            },
        }
    }
}

impl WalletClientConfig {
    pub fn new(
        peg_in_descriptor: PegInDescriptor,
        network: bitcoin::network::constants::Network,
        finality_delay: u32,
        default_bitcoin_rpc: BitcoinRpcConfig,
    ) -> Self {
        Self {
            peg_in_descriptor,
            network,
            finality_delay,
            fee_consensus: Default::default(),
            default_bitcoin_rpc,
        }
    }
}

plugin_types_trait_impl_config!(
    WalletCommonGen,
    WalletGenParams,
    WalletGenParamsLocal,
    WalletGenParamsConsensus,
    WalletConfig,
    WalletConfigLocal,
    WalletConfigPrivate,
    WalletConfigConsensus,
    WalletClientConfig
);
