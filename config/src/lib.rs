use bitcoin::{Amount, Network};
use mint_api::{CompressedPublicKey, FeeConsensus, Keys, PegInDescriptor};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use structopt::StructOpt;
#[cfg(feature = "client")]
use tbs::AggregatePublicKey;

#[cfg(feature = "server")]
#[derive(StructOpt)]
pub struct ServerOpts {
    pub cfg_path: PathBuf,
}

#[derive(Copy, Clone, Debug, PartialEq, Ord, PartialOrd, Eq, Hash, Serialize, Deserialize)]
pub struct Feerate {
    pub sats_per_kvb: u64,
}

// TODO: put config back into functional crates, make cfg-gen dependent on all
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    pub network: Network,
    pub peg_in_descriptor: PegInDescriptor,
    pub peer_peg_in_keys: BTreeMap<u16, CompressedPublicKey>,
    pub peg_in_key: secp256k1::SecretKey,
    pub finalty_delay: u32,
    pub default_fee: Feerate,
    #[serde(with = "bitcoin::util::amount::serde::as_sat")]
    pub per_utxo_fee: Amount,
    pub btc_rpc_address: String,
    pub btc_rpc_user: String,
    pub btc_rpc_pass: String,
}

#[cfg(feature = "server")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub identity: u16,
    pub hbbft_port: u16,
    pub api_port: u16,

    pub peers: BTreeMap<u16, Peer>,
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_sk: hbbft::crypto::serde_impl::SerdeSecret<hbbft::crypto::SecretKey>,
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_sks: hbbft::crypto::serde_impl::SerdeSecret<hbbft::crypto::SecretKeyShare>,
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_pk_set: hbbft::crypto::PublicKeySet,
    pub tbs_sks: Keys<tbs::SecretKeyShare>,

    pub db_path: PathBuf,

    pub wallet: WalletConfig,
    // TODO: make consensus defined
    pub fee_consensus: FeeConsensus,
}

#[cfg(feature = "server")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub hbbft_port: u16,
    pub api_port: u16,
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_pk: hbbft::crypto::PublicKey,
    pub tbs_pks: Keys<tbs::PublicKeyShare>,
}

#[cfg(feature = "server")]
impl ServerConfig {
    pub fn get_hbbft_port(&self) -> u16 {
        self.hbbft_port
    }
    pub fn get_api_port(&self) -> u16 {
        self.api_port
    }

    pub fn get_incoming_count(&self) -> u16 {
        self.identity
    }

    pub fn max_faulty(&self) -> usize {
        hbbft::util::max_faulty(self.peers.len())
    }
}

#[cfg(feature = "client")]
#[derive(StructOpt)]
pub struct ClientOpts {
    pub cfg_path: PathBuf,
    pub issue_amt: usize,
    pub issuance_per_1000_s: usize,
}

#[cfg(feature = "client")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub mints: Vec<String>,
    pub mint_pk: Keys<AggregatePublicKey>,
    pub peg_in_descriptor: PegInDescriptor,
    pub network: Network,
    pub fee_consensus: FeeConsensus,
}

pub fn load_from_file<T: DeserializeOwned>(path: &Path) -> T {
    let file = std::fs::File::open(path).expect("Can't read cfg file.");
    serde_json::from_reader(file).expect("Could not parse cfg file.")
}

impl Feerate {
    pub fn calculate_fee(&self, weight: usize) -> bitcoin::Amount {
        let sats = self.sats_per_kvb * (weight as u64) / 1000;
        bitcoin::Amount::from_sat(sats)
    }
}

#[cfg(any(feature = "client", feature = "server"))]
mod serde_binary_human_readable {
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
