use fedimint_ln::config::LightningModuleClientConfig;
use fedimint_mint::config::MintClientConfig;
use fedimint_wallet::config::WalletClientConfig;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::path::Path;
use url::Url;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ClientConfig {
    pub api_endpoints: Vec<Url>,
    pub mint: MintClientConfig,
    pub wallet: WalletClientConfig,
    pub ln: LightningModuleClientConfig,
    pub max_evil: usize,
}

impl ClientConfig {
    pub fn fee_consensus(&self) -> FeeConsensus {
        FeeConsensus {
            wallet: self.wallet.fee_consensus.clone(),
            mint: self.mint.fee_consensus.clone(),
            ln: self.ln.fee_consensus.clone(),
        }
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct FeeConsensus {
    pub wallet: fedimint_wallet::config::FeeConsensus,
    pub mint: fedimint_mint::config::FeeConsensus,
    pub ln: fedimint_ln::config::FeeConsensus,
}

pub fn load_from_file<T: DeserializeOwned>(path: &Path) -> T {
    let file = std::fs::File::open(path).expect("Can't read cfg file.");
    serde_json::from_reader(file).expect("Could not parse cfg file.")
}

pub mod serde_binary_human_readable {
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T: Serialize, S: Serializer>(x: &T, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            let bytes =
                bincode::serialize(x).map_err(|e| serde::ser::Error::custom(format!("{:?}", e)))?;
            s.serialize_str(&hex::encode(&bytes))
        } else {
            Serialize::serialize(x, s)
        }
    }

    pub fn deserialize<'d, T: DeserializeOwned, D: Deserializer<'d>>(d: D) -> Result<T, D::Error> {
        if d.is_human_readable() {
            let bytes = hex::decode::<String>(Deserialize::deserialize(d)?)
                .map_err(serde::de::Error::custom)?;
            bincode::deserialize(&bytes).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
        } else {
            Deserialize::deserialize(d)
        }
    }
}
