#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::needless_lifetimes)]

pub mod endpoint;

use std::fmt;
use std::str::FromStr;

use config::MetaClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::plugin_types_trait_impl_common;
use fedimint_logging::LOG_MODULE_META;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use tracing::warn;
// Common contains types shared by both the client and server

// The client and server configuration
pub mod config;

/// Unique name for this module
pub const KIND: ModuleKind = ModuleKind::from_static_str("meta");

/// Modules are non-compatible with older versions
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);

/// The meta module was built with flexibility and upgradability in mind. We
/// currently only intend to use one key, which is defined here.
pub const DEFAULT_META_KEY: MetaKey = MetaKey(0);

/// A key identifying a value in the meta module consensus
///
/// Intentionally small (`u8`) to avoid problems with malicious peers
/// submitting lots of votes to waste storage and memory. Since values
/// in the meta module are supposed to be larger aggregates (e.g. json),
/// 256 keys should be plenty.
#[derive(
    Debug,
    Copy,
    Clone,
    Encodable,
    Decodable,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct MetaKey(pub u8);

impl fmt::Display for MetaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for MetaKey {
    type Err = <u8 as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(FromStr::from_str(s)?))
    }
}
/// A value of the [`MetaKey`] peers are trying to establish consensus on
///
/// Mostly a newtype around a `Vec<u8>` as meta module does not ever interpret
/// it. Serialized as a hex string, with [`Decodable`] and [`Deserialize`]
/// implementations enforcing size limit of [`Self::MAX_LEN_BYTES`].
#[derive(Debug, Clone, Encodable, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MetaValue(Vec<u8>);

impl FromStr for MetaValue {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(hex::decode(s)?))
    }
}

impl fmt::Display for MetaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(&self.0))
    }
}
impl From<&[u8]> for MetaValue {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl MetaValue {
    /// Maximum size of a [`MetaValue`]
    /// More than 1MB would lead to problems.
    pub const MAX_LEN_BYTES: usize = 1024 * 1024 * 1024;

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn to_json(&self) -> anyhow::Result<serde_json::Value> {
        Ok(serde_json::from_slice(&self.0)?)
    }

    /// Converts the value to a JSON value, ignoring invalid utf-8.
    pub fn to_json_lossy(&self) -> anyhow::Result<serde_json::Value> {
        let maybe_lossy_str = String::from_utf8_lossy(self.as_slice());

        if maybe_lossy_str.as_bytes() != self.as_slice() {
            warn!(target: LOG_MODULE_META, "Value contains invalid utf-8, converting to lossy string");
        }

        Ok(serde_json::from_str(&maybe_lossy_str)?)
    }
}

impl Decodable for MetaValue {
    fn consensus_decode_partial<R: std::io::Read>(
        r: &mut R,
        modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let bytes = Vec::consensus_decode_partial(r, modules)?;

        if Self::MAX_LEN_BYTES < bytes.len() {
            return Err(DecodeError::new_custom(anyhow::format_err!("Too long")));
        }

        Ok(Self(bytes))
    }
}
impl Serialize for MetaValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        assert!(self.0.len() <= Self::MAX_LEN_BYTES);
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

// Implement Deserialize for MetaValue
impl<'de> Deserialize<'de> for MetaValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct MetaValueVisitor;

        impl<'de> Visitor<'de> for MetaValueVisitor {
            type Value = MetaValue;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a hex string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let val = hex::decode(value).map_err(de::Error::custom)?;

                if MetaValue::MAX_LEN_BYTES < val.len() {
                    return Err(de::Error::custom("Too long"));
                }

                Ok(MetaValue(val))
            }
        }

        deserializer.deserialize_str(MetaValueVisitor)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct MetaConsensusItem {
    // Since AlephBft will merge and not re-submit the exact same item twice within one session,
    // changing submitted item in sequence `a -> b -> a` will simply ignore the second `a`.
    // To avoid this behavior, an otherwise meaningless `salt` field is used.
    pub salt: u64,
    pub key: MetaKey,
    pub value: MetaValue,
}

/// A [`MetaValue`] in a consensus (which means it has a revision number)
#[derive(Debug, Clone, Encodable, Decodable, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetaConsensusValue {
    pub revision: u64,
    pub value: MetaValue,
}

/// Input for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct MetaInput;

/// Output for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct MetaOutput;

/// Information needed by a client to update output funds
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct MetaOutputOutcome;

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum MetaInputError {
    #[error("This module does not support inputs")]
    NotSupported,
}

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum MetaOutputError {
    #[error("This module does not support outputs")]
    NotSupported,
}

/// Contains the types defined above
pub struct MetaModuleTypes;

// Wire together the types for this module
plugin_types_trait_impl_common!(
    KIND,
    MetaModuleTypes,
    MetaClientConfig,
    MetaInput,
    MetaOutput,
    MetaOutputOutcome,
    MetaConsensusItem,
    MetaInputError,
    MetaOutputError
);

#[derive(Debug)]
pub struct MetaCommonInit;

impl CommonModuleInit for MetaCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = MetaClientConfig;

    fn decoder() -> Decoder {
        MetaModuleTypes::decoder_builder().build()
    }
}

impl fmt::Display for MetaClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MetaClientConfig")
    }
}
impl fmt::Display for MetaInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MetaInput")
    }
}

impl fmt::Display for MetaOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MetaOutput")
    }
}

impl fmt::Display for MetaOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MetaOutputOutcome")
    }
}

impl fmt::Display for MetaConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MetaConsensusItem")
    }
}
