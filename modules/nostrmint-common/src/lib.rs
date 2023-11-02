use core::hash::Hash;
use std::fmt;

use config::NostrmintClientConfig;
use fedimint_core::core::{Decoder, ModuleKind};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleInstanceId;
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::plugin_types_trait_impl_common;
use nostr_sdk::UnsignedEvent as NdkUnsignedEvent;
use schnorr_fun::fun::marker::{Public, Zero};
use schnorr_fun::fun::Scalar;
use schnorr_fun::musig::NonceKeyPair;
use serde::{Deserialize, Serialize};

pub mod api;
pub mod config;

/// Unique name for this module
pub const KIND: ModuleKind = ModuleKind::from_static_str("nostrmint");

/// Modules are non-compatible with older versions
pub const CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion(0);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum NostrmintConsensusItem {
    Nonce(UnsignedEvent, NostrmintNonceKeyPair),
    FrostSigShare(UnsignedEvent, NostrmintSignatureShare),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct NostrmintInput;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct NostrmintOutput;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct NostrmintOutputOutcome;

pub struct NostrmintModuleTypes;

plugin_types_trait_impl_common!(
    NostrmintModuleTypes,
    NostrmintClientConfig,
    NostrmintInput,
    NostrmintOutput,
    NostrmintOutputOutcome,
    NostrmintConsensusItem
);

#[derive(Debug)]
pub struct NostrmintCommonGen;

impl CommonModuleInit for NostrmintCommonGen {
    const CONSENSUS_VERSION: ModuleConsensusVersion = CONSENSUS_VERSION;

    const KIND: ModuleKind = KIND;

    type ClientConfig = NostrmintClientConfig;

    fn decoder() -> Decoder {
        NostrmintModuleTypes::decoder_builder().build()
    }
}

impl fmt::Display for NostrmintClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NostrmintClientConfig")
    }
}

impl fmt::Display for NostrmintInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NostrmintInput")
    }
}

impl fmt::Display for NostrmintOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NostrmintOutput")
    }
}

impl fmt::Display for NostrmintOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NostrmintOutputOutcome")
    }
}

impl fmt::Display for NostrmintConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NostrmintConsensusItem")
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Deserialize)]
pub struct NostrmintNonceKeyPair(pub NonceKeyPair);

impl Hash for NostrmintNonceKeyPair {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let mut bytes = Vec::new();
        self.consensus_encode(&mut bytes).unwrap();
        state.write(&bytes);
    }
}

impl Eq for NostrmintNonceKeyPair {}

impl Encodable for NostrmintNonceKeyPair {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let bytes = self.0.to_bytes();
        writer.write(&bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for NostrmintNonceKeyPair {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let mut bytes = [0; 64];
        r.read_exact(&mut bytes)
            .map_err(|_| DecodeError::from_str("Failed to decode NostrmintNonceKeyPair"))?;
        match NonceKeyPair::from_bytes(bytes) {
            Some(nonce_keypair) => Ok(NostrmintNonceKeyPair(nonce_keypair)),
            None => Err(DecodeError::from_str(
                "Failed to create NonceKeyPair from bytes",
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Deserialize, Eq, Hash)]
pub struct NostrmintSignatureShare(pub Scalar<Public, Zero>);

impl Encodable for NostrmintSignatureShare {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let bytes = self.0.to_bytes();
        writer.write(&bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for NostrmintSignatureShare {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bytes = [0; 32];
        r.read_exact(&mut bytes)
            .map_err(|_| DecodeError::from_str("Failed to decode NostrmintSignatureShare"))?;
        match Scalar::from_bytes(bytes) {
            Some(share) => Ok(NostrmintSignatureShare(share)),
            None => Err(DecodeError::from_str(
                "Failed to create NostrmintSignatureShare from bytes",
            )),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct UnsignedEvent(pub NdkUnsignedEvent);

impl Encodable for UnsignedEvent {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.0.as_json().as_bytes().consensus_encode(writer)
    }
}

impl Decodable for UnsignedEvent {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let bytes = Vec::<u8>::consensus_decode(r, modules)?;
        let json = String::from_utf8(bytes).unwrap();
        let event = nostr_sdk::UnsignedEvent::from_json(json).unwrap();
        Ok(UnsignedEvent(event))
    }
}
