use fedimint_api::rand::Rand07Compat;
pub use fedimint_core::config::*;

use crate::net::peers::{ConnectionConfig, NetworkConfig};
use fedimint_api::config::GenerateConfig;
use fedimint_api::PeerId;
use fedimint_core::modules::ln::config::LightningModuleConfig;
use fedimint_core::modules::mint::config::MintConfig;
use fedimint_core::modules::wallet::config::WalletConfig;
use hbbft::crypto::serde_impl::SerdeSecret;
use rand::{CryptoRng, RngCore};
use url::Url;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use crate::net::connect::TlsConfig;
use tokio_rustls::rustls;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub identity: PeerId,
    pub hbbft_bind_addr: String,
    pub api_bind_addr: String,
    #[serde(with = "serde_tls_cert")]
    pub tls_cert: rustls::Certificate,
    #[serde(with = "serde_tls_key")]
    pub tls_key: rustls::PrivateKey,

    pub peers: BTreeMap<PeerId, Peer>,
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_sks: SerdeSecret<hbbft::crypto::SecretKeyShare>,
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_pk_set: hbbft::crypto::PublicKeySet,

    #[serde(with = "serde_binary_human_readable")]
    pub epoch_sks: SerdeSecret<hbbft::crypto::SecretKeyShare>,
    #[serde(with = "serde_binary_human_readable")]
    pub epoch_pk_set: hbbft::crypto::PublicKeySet,

    pub wallet: WalletConfig,
    pub mint: MintConfig,
    pub ln: LightningModuleConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub connection: ConnectionConfig,
    #[serde(with = "serde_tls_cert")]
    pub tls_cert: rustls::Certificate,
}

#[derive(Debug)]
pub struct ServerConfigParams {
    pub hbbft_base_port: u16,
    pub api_base_port: u16,
    pub amount_tiers: Vec<fedimint_api::Amount>,
}

impl GenerateConfig for ServerConfig {
    type Params = ServerConfigParams;
    type ClientConfig = ClientConfig;

    fn trusted_dealer_gen(
        peers: &[PeerId],
        max_evil: usize,
        params: &Self::Params,
        mut rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let netinfo = hbbft::NetworkInfo::generate_map(peers.to_vec(), &mut Rand07Compat(&mut rng))
            .expect("Could not generate HBBFT netinfo");
        let epochinfo =
            hbbft::NetworkInfo::generate_map(peers.to_vec(), &mut Rand07Compat(&mut rng))
                .expect("Could not generate HBBFT netinfo");

        let tls_keys = peers
            .iter()
            .map(|peer| {
                let (cert, key) = gen_cert_and_key(&format!("peer-{}", peer.to_usize())).unwrap();
                (*peer, (cert, key))
            })
            .collect::<HashMap<_, _>>();

        let cfg_peers = netinfo
            .iter()
            .map(|(&id, _)| {
                let id_u16: u16 = id.into();
                let peer = Peer {
                    connection: ConnectionConfig {
                        hbbft_addr: format!("127.0.0.1:{}", params.hbbft_base_port + id_u16),
                        api_addr: Url::parse(
                            format!("ws://127.0.0.1:{}", params.api_base_port + id_u16).as_str(),
                        )
                        .expect("Could not parse URL"),
                    },
                    tls_cert: tls_keys[&id].0.clone(),
                };

                (id, peer)
            })
            .collect::<BTreeMap<_, _>>();

        let (wallet_server_cfg, wallet_client_cfg) =
            WalletConfig::trusted_dealer_gen(peers, max_evil, &(), &mut rng);
        let (mint_server_cfg, mint_client_cfg) =
            MintConfig::trusted_dealer_gen(peers, max_evil, params.amount_tiers.as_ref(), &mut rng);
        let (ln_server_cfg, ln_client_cfg) =
            LightningModuleConfig::trusted_dealer_gen(peers, max_evil, &(), &mut rng);

        let server_config = netinfo
            .iter()
            .map(|(&id, netinf)| {
                let id_u16: u16 = id.into();
                let epoch_keys = epochinfo.get(&id).unwrap();
                let config = ServerConfig {
                    identity: id,
                    hbbft_bind_addr: format!("127.0.0.1:{}", params.hbbft_base_port + id_u16),
                    api_bind_addr: format!("127.0.0.1:{}", params.api_base_port + id_u16),
                    tls_cert: tls_keys[&id].0.clone(),
                    tls_key: tls_keys[&id].1.clone(),
                    peers: cfg_peers.clone(),
                    hbbft_sks: SerdeSecret(netinf.secret_key_share().unwrap().clone()),
                    hbbft_pk_set: netinf.public_key_set().clone(),
                    epoch_sks: SerdeSecret(epoch_keys.secret_key_share().unwrap().clone()),
                    epoch_pk_set: epoch_keys.public_key_set().clone(),
                    wallet: wallet_server_cfg[&id].clone(),
                    mint: mint_server_cfg[&id].clone(),
                    ln: ln_server_cfg[&id].clone(),
                };
                (id, config)
            })
            .collect();

        let client_config = ClientConfig {
            max_evil,
            api_endpoints: peers
                .iter()
                .map(|&peer| {
                    Url::parse(
                        format!("ws://127.0.0.1:{}", params.api_base_port + u16::from(peer))
                            .as_str(),
                    )
                    .expect("Could not parse Url")
                })
                .collect(),
            mint: mint_client_cfg,
            wallet: wallet_client_cfg,
            ln: ln_client_cfg,
        };

        (server_config, client_config)
    }

    fn to_client_config(&self) -> Self::ClientConfig {
        let api_endpoints: Vec<Url> = self
            .peers
            .iter()
            .map(|(_, peer)| peer.connection.api_addr.clone())
            .collect();
        let max_evil = hbbft::util::max_faulty(self.peers.len());
        ClientConfig {
            api_endpoints,
            max_evil,
            mint: self.mint.to_client_config(),
            wallet: self.wallet.to_client_config(),
            ln: self.ln.to_client_config(),
        }
    }
}

impl ServerConfig {
    pub fn network_config(&self) -> NetworkConfig {
        NetworkConfig {
            identity: self.identity,
            bind_addr: self.hbbft_bind_addr.clone(),
            peers: self
                .peers
                .iter()
                .map(|(&id, peer)| (id, peer.connection.clone()))
                .collect(),
        }
    }

    pub fn tls_config(&self) -> TlsConfig {
        TlsConfig {
            our_certificate: self.tls_cert.clone(),
            our_private_key: self.tls_key.clone(),
            peer_certs: self
                .peers
                .iter()
                .map(|(peer, cfg)| (*peer, cfg.tls_cert.clone()))
                .collect(),
        }
    }

    pub fn get_incoming_count(&self) -> u16 {
        self.identity.into()
    }

    pub fn max_faulty(&self) -> usize {
        hbbft::util::max_faulty(self.peers.len())
    }

    pub fn fee_consensus(&self) -> fedimint_core::config::FeeConsensus {
        fedimint_core::config::FeeConsensus {
            wallet: self.wallet.fee_consensus.clone(),
            mint: self.mint.fee_consensus.clone(),
            ln: self.ln.fee_consensus.clone(),
        }
    }
}

pub(crate) fn gen_cert_and_key(
    name: &str,
) -> Result<(rustls::Certificate, rustls::PrivateKey), anyhow::Error> {
    let keypair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let keypair_ser = keypair.serialize_der();
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]);

    params.key_pair = Some(keypair);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.is_ca = rcgen::IsCa::SelfSignedOnly;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);

    let cert = rcgen::Certificate::from_params(params)?;

    Ok((
        rustls::Certificate(cert.serialize_der()?),
        rustls::PrivateKey(keypair_ser),
    ))
}

mod serde_tls_cert {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::borrow::Cow;
    use tokio_rustls::rustls;

    pub fn serialize<S>(cert: &rustls::Certificate, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = hex::encode(&cert.0);
        Serialize::serialize(&hex_str, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<rustls::Certificate, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: Cow<str> = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(hex_str.as_ref()).map_err(|_e| D::Error::custom("Invalid hex"))?;
        Ok(rustls::Certificate(bytes))
    }
}

mod serde_tls_key {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::borrow::Cow;
    use tokio_rustls::rustls;

    pub fn serialize<S>(key: &rustls::PrivateKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = hex::encode(&key.0);
        Serialize::serialize(&hex_str, serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<rustls::PrivateKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: Cow<str> = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(hex_str.as_ref()).map_err(|_e| D::Error::custom("Invalid hex"))?;
        Ok(rustls::PrivateKey(bytes))
    }
}
