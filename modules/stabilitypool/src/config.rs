use std::path::PathBuf;
use std::str::FromStr;

use fedimint_api::config::{
    TypedClientModuleConfig, TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_api::encoding::Encodable;
use fedimint_api::module::__reexports::serde_json;
use fedimint_api::PeerId;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::price::{BitMexOracle, MockOracle, OracleClient};
use crate::stability_core::CollateralRatio;
use crate::{FileOracle, KIND};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolConfig {
    /// Configuration that will be encrypted.
    pub private: PoolConfigPrivate,
    /// Configuration that needs to be the same for every federation member.
    pub consensus: PoolConfigConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoolConfigPrivate {
    pub peer_id: PeerId,
}

#[derive(Clone, Debug, Serialize, Deserialize, Encodable)]
pub struct PoolConfigConsensus {
    // TODO: What fields do we need?
    pub epoch: EpochConfig,
    pub oracle: OracleConfig,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable)]
pub enum OracleConfig {
    BitMex,
    Mock(String),
    File(String),
}

impl Default for OracleConfig {
    fn default() -> Self {
        OracleConfig::File("./misc/offline_oracle".to_string())
    }
}

impl OracleConfig {
    pub fn oracle_client(&self) -> Box<dyn OracleClient> {
        match self {
            OracleConfig::BitMex => Box::new(BitMexOracle {}),
            OracleConfig::Mock(url) => Box::new(MockOracle {
                url: reqwest::Url::parse(url).expect("invalid Url"),
            }),
            OracleConfig::File(path) => {
                let path = PathBuf::from_str(&path).expect("must be valid path");
                Box::new(FileOracle { path })
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Encodable)]
pub struct EpochConfig {
    pub start_epoch_at: u64,
    pub epoch_length: u64,
    /// Number of peers that have to agree on price before it's used
    pub price_threshold: u32,
    /// The maximum a provider can charge per epoch in parts per million of locked principal
    pub max_feerate_ppm: u64,
    /// The ratio of seeker position to provider collateral
    pub collateral_ratio: CollateralRatio,
}

impl EpochConfig {
    pub fn epoch_id_for_time(&self, time: OffsetDateTime) -> u64 {
        if time < self.start_epoch_at() {
            0
        } else {
            (time - self.start_epoch_at()).whole_seconds() as u64 / self.epoch_length + 1
        }
    }

    pub fn start_epoch_at(&self) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(self.start_epoch_at as _)
            .expect("must be valid unix timestamp")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable)]
pub struct PoolConfigClient {
    pub oracle: OracleConfig,
    pub collateral_ratio: CollateralRatio,
}

impl TypedServerModuleConfig for PoolConfig {
    type Local = ();
    type Private = PoolConfigPrivate;
    type Consensus = PoolConfigConsensus;

    fn from_parts(_: Self::Local, private: Self::Private, consensus: Self::Consensus) -> Self {
        Self { private, consensus }
    }

    fn to_parts(
        self,
    ) -> (
        fedimint_api::core::ModuleKind,
        Self::Local,
        Self::Private,
        Self::Consensus,
    ) {
        (KIND, (), self.private, self.consensus)
    }

    fn validate_config(&self, _identity: &fedimint_api::PeerId) -> anyhow::Result<()> {
        Ok(())
    }
}

impl TypedServerModuleConsensusConfig for PoolConfigConsensus {
    fn to_client_config(&self) -> fedimint_api::config::ClientModuleConfig {
        fedimint_api::config::ClientModuleConfig::new(
            KIND,
            serde_json::to_value(&PoolConfigClient {
                oracle: self.oracle.clone(),
                collateral_ratio: self.epoch.collateral_ratio,
            })
            .expect("serialization cannot fail"),
        )
    }
}

impl TypedClientModuleConfig for PoolConfigClient {
    fn kind(&self) -> fedimint_api::core::ModuleKind {
        KIND
    }
}
