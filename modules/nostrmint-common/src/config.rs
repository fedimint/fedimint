use std::io::ErrorKind;

use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::{plugin_types_trait_impl_config, PeerId};
use schnorr_fun::frost::FrostKey;
use schnorr_fun::fun::marker::{Normal, Secret};
use schnorr_fun::fun::Scalar;
use serde::{Deserialize, Serialize};

use crate::NostrmintCommonGen;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NostrmintGenParams {
    pub local: NostrmintGenParamsLocal,
    pub consensus: NostrmintGenParamsConsensus,
}

impl Default for NostrmintGenParams {
    fn default() -> Self {
        Self {
            local: NostrmintGenParamsLocal {},
            consensus: NostrmintGenParamsConsensus { threshold: 3 },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NostrmintGenParamsLocal;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NostrmintGenParamsConsensus {
    pub threshold: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NostrmintConfig {
    pub local: NostrmintConfigLocal,
    pub private: NostrmintConfigPrivate,
    pub consensus: NostrmintConfigConsensus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct NostrmintClientConfig;

#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct NostrmintConfigLocal;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NostrmintConfigConsensus {
    pub threshold: u32,
    pub frost_key: FrostKey<Normal>,
}

// TODO: How do we save the FrostKey from DKG??
impl Encodable for NostrmintConfigConsensus {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let threshold_bytes = self.threshold.to_le_bytes();
        let frost_key_bytes = bincode::serialize(&self.frost_key).map_err(|_| {
            std::io::Error::new(ErrorKind::Other, format!("Error serializing FrostKey"))
        })?;
        writer.write(&threshold_bytes.as_slice())?;
        writer.write(&frost_key_bytes.as_slice())?;
        Ok(threshold_bytes.len() + frost_key_bytes.len())
    }
}

impl Decodable for NostrmintConfigConsensus {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let mut threshold_bytes = [0; 4]; // Assuming u32 threshold
        r.read_exact(&mut threshold_bytes)
            .map_err(|_| DecodeError::from_str("Failed to read threshold bytes"))?;
        let threshold = u32::from_le_bytes(threshold_bytes);

        // Now, you need to read and deserialize the FrostKey
        let mut frost_key_bytes = Vec::new();
        r.read_to_end(&mut frost_key_bytes)
            .map_err(|_| DecodeError::from_str("Failed to read FrostKey bytes"))?;
        let frost_key: FrostKey<Normal> = bincode::deserialize(&frost_key_bytes)
            .map_err(|_| DecodeError::from_str("Error deserializing FrostKey"))?;

        // Create and return the NostrmintConfigConsensus
        Ok(NostrmintConfigConsensus {
            threshold,
            frost_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NostrmintConfigPrivate {
    pub my_secret_share: Scalar<Secret>,
    pub my_peer_id: PeerId,
}

plugin_types_trait_impl_config!(
    NostrmintCommonGen,
    NostrmintGenParams,
    NostrmintGenParamsLocal,
    NostrmintGenParamsConsensus,
    NostrmintConfig,
    NostrmintConfigLocal,
    NostrmintConfigPrivate,
    NostrmintConfigConsensus,
    NostrmintClientConfig
);
