use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use structopt::StructOpt;
use tbs::AggregatePublicKey;

#[derive(StructOpt)]
pub struct ServerOpts {
    pub cfg_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub identity: u16,
    pub hbbft_port: u16,
    pub api_port: u16,

    pub peers: BTreeMap<u16, Peer>,
    pub hbbft_sk: hbbft::crypto::serde_impl::SerdeSecret<hbbft::crypto::SecretKey>,
    pub hbbft_sks: hbbft::crypto::serde_impl::SerdeSecret<hbbft::crypto::SecretKeyShare>,
    pub hbbft_pk_set: hbbft::crypto::PublicKeySet,
    pub tbs_sks: tbs::SecretKeyShare,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub hbbft_port: u16,
    pub api_port: u16,
    pub hbbft_pk: hbbft::crypto::PublicKey,
    pub tbs_pks: tbs::PublicKeyShare,
}

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

#[derive(StructOpt)]
pub struct ClientOpts {
    pub cfg_path: PathBuf,
    pub issue_amt: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub url: String,
    pub mint_pk: AggregatePublicKey,
}

pub fn load_from_file<T: DeserializeOwned>(path: &Path) -> T {
    let mut file = std::fs::File::open(path).expect("Can't read cfg file.");
    serde_json::from_reader(file).expect("Could not parse cfg file.")
}
