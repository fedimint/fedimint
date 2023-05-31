use std::collections::BTreeMap;

use bitcoin::Network;
use fedimint_core::bitcoinrpc::BitcoinRpcConfig;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{plugin_types_trait_impl_config, Feerate, PeerId};
use miniscript::descriptor::Wsh;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use url::Url;

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
    // TODO: move elsewhere, not really consensus
    /// The default electrs server for clients to connect to
    pub default_esplora_server: Url,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable)]
pub struct WalletClientConfig {
    /// The federations public peg-in-descriptor
    pub peg_in_descriptor: PegInDescriptor,
    /// The bitcoin network the client will use
    pub network: Network,
    /// Confirmations required for a peg in to be accepted by federation
    pub finality_delay: u32,
    pub fee_consensus: FeeConsensus,
    /// Default electrs server for clients to connect to
    pub default_esplora_server: Url,
}

impl Decodable for WalletClientConfig {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let peg_in_descriptor = PegInDescriptor::consensus_decode(r, modules)?;

        let network = Network::consensus_decode(r, modules)?;
        let finality_delay = u32::consensus_decode(r, modules)?;
        let fee_consensus = FeeConsensus::consensus_decode(r, modules)?;
        // This is to make the config backwards compatible with old federations. It may
        // be removed in future
        let default_esplora_server = match Url::consensus_decode(r, modules) {
            Ok(url) => url,
            Err(_) => Url::parse(&std::env::var("FM_ESPLORA_SERVER").map_err(|e| {
                fedimint_core::encoding::DecodeError::new_custom(anyhow::anyhow!(
                    "error reading FM_ESPLORA_SERVER from environment: {e:?}"
                ))
            })?)
            .map_err(|e| {
                fedimint_core::encoding::DecodeError::new_custom(anyhow::anyhow!(
                    "error parsing FM_ESPLORA_SERVER from environment: {e:?}"
                ))
            })?,
        };
        Ok(Self {
            peg_in_descriptor,
            network,
            finality_delay,
            fee_consensus,
            default_esplora_server,
        })
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
    pub fn new(
        pubkeys: BTreeMap<PeerId, CompressedPublicKey>,
        sk: SecretKey,
        threshold: usize,
        network: Network,
        finality_delay: u32,
        bitcoin_rpc: BitcoinRpcConfig,
        default_esplora_server: Url,
    ) -> Self {
        let peg_in_descriptor = PegInDescriptor::Wsh(
            Wsh::new_sortedmulti(threshold, pubkeys.values().copied().collect()).unwrap(),
        );

        Self {
            local: WalletConfigLocal { bitcoin_rpc },
            private: WalletConfigPrivate { peg_in_key: sk },
            consensus: WalletConfigConsensus {
                network,
                peg_in_descriptor,
                peer_peg_in_keys: pubkeys,
                finality_delay,
                default_fee: Feerate { sats_per_kvb: 1000 },
                fee_consensus: Default::default(),
                default_esplora_server,
            },
        }
    }
}

pub fn default_esplora_server(network: Network) -> Url {
    match network {
        Network::Bitcoin => Url::parse("https://blockstream.info/api/")
            .expect("Failed to parse default esplora server"),
        Network::Testnet => Url::parse("https://blockstream.info/testnet/api/")
            .expect("Failed to parse default esplora server"),
        Network::Regtest => {
            Url::parse("http://127.0.0.1:50002/").expect("Failed to parse default esplora server")
        }
        network => {
            panic!("Don't know an electrs server for network: {network}");
        }
    }
}

impl WalletClientConfig {
    pub fn new(
        peg_in_descriptor: PegInDescriptor,
        network: bitcoin::network::constants::Network,
        finality_delay: u32,
        default_esplora_server: Url,
    ) -> Self {
        Self {
            peg_in_descriptor,
            network,
            finality_delay,
            fee_consensus: Default::default(),
            default_esplora_server,
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
