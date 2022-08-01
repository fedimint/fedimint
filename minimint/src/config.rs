use minimint_api::rand::Rand07Compat;
pub use minimint_core::config::*;

use crate::net::peers::{ConnectionConfig, NetworkConfig};
use hbbft::crypto::serde_impl::SerdeSecret;
use minimint_api::config::GenerateConfig;
use minimint_api::PeerId;
use minimint_core::modules::ln::config::LightningModuleConfig;
use minimint_core::modules::mint::config::{MintClientConfig, MintConfig};
use minimint_core::modules::wallet::config::WalletConfig;
use rand::{CryptoRng, RngCore};

use crate::minimint_api::net::peers::PeerConnections;
use crate::net::connect::Connector;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use crate::net::connect::TlsConfig;
use crate::{ReconnectPeerConnections, TlsTcpConnector};
use async_trait::async_trait;

use threshold_crypto::{PublicKeySet, SecretKeyShare};

use minimint_api::net::peers::AnyPeerConnections;

use serde::de::DeserializeOwned;
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
    pub hbbft_sks: SerdeSecret<SecretKeyShare>,
    #[serde(with = "serde_binary_human_readable")]
    pub hbbft_pk_set: PublicKeySet,

    pub wallet: WalletConfig,
    pub mint: MintConfig,
    pub ln: LightningModuleConfig,

    // TODO: make consensus defined
    pub fee_consensus: FeeConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub connection: ConnectionConfig,
    #[serde(with = "serde_tls_cert")]
    pub tls_cert: rustls::Certificate,
}

#[derive(Debug, Clone)]
pub struct ServerConfigParams {
    pub hbbft_base_port: u16,
    pub api_base_port: u16,
    pub keygen_base_port: u16,
    pub wallet_base_port: u16,
    pub lightning_base_port: u16,
    pub amount_tiers: Vec<minimint_api::Amount>,
}

pub struct RemoteServerConfig {
    pub tls: TlsConfig,
    pub hbbft: NetworkConfig,
    pub wallet: AnyPeerConnections<<WalletConfig as GenerateConfig>::ConfigMessage>,
    pub lightning: AnyPeerConnections<<LightningModuleConfig as GenerateConfig>::ConfigMessage>,
    pub configs: (MintConfig, MintClientConfig),
}

#[async_trait(?Send)]
impl GenerateConfig for ServerConfig {
    type Params = (ServerConfigParams, Option<RemoteServerConfig>);
    type ClientConfig = ClientConfig;
    type ConfigMessage = <LightningModuleConfig as GenerateConfig>::ConfigMessage;
    type ConfigError = ();

    fn trusted_dealer_gen(
        peers: &[PeerId],
        max_evil: usize,
        params: &Self::Params,
        mut rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let (params, _) = params;
        let netinfo = hbbft::NetworkInfo::generate_map(peers.to_vec(), &mut Rand07Compat(&mut rng))
            .expect("Could not generate HBBFT netinfo");
        let tls_keys = gen_tls_configs(peers);

        let cfg_peers = netinfo
            .iter()
            .map(|(&id, _netinf)| {
                let id_u16: u16 = id.into();
                let peer = Peer {
                    connection: ConnectionConfig {
                        addr: format!("127.0.0.1:{}", params.hbbft_base_port + id_u16),
                    },
                    tls_cert: tls_keys[&id].our_certificate.clone(),
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

        let fee_consensus = FeeConsensus {
            fee_coin_spend_abs: minimint_api::Amount::ZERO,
            fee_peg_in_abs: minimint_api::Amount::ZERO,
            fee_coin_issuance_abs: minimint_api::Amount::ZERO,
            fee_peg_out_abs: minimint_api::Amount::ZERO,
            fee_contract_input: minimint_api::Amount::ZERO,
            fee_contract_output: minimint_api::Amount::ZERO,
        };

        let server_config = netinfo
            .iter()
            .map(|(&id, netinf)| {
                let id_u16: u16 = id.into();
                let config = ServerConfig {
                    identity: id,
                    hbbft_bind_addr: format!("127.0.0.1:{}", params.hbbft_base_port + id_u16),
                    api_bind_addr: format!("127.0.0.1:{}", params.api_base_port + id_u16),
                    tls_cert: tls_keys[&id].our_certificate.clone(),
                    tls_key: tls_keys[&id].our_private_key.clone(),
                    peers: cfg_peers.clone(),
                    hbbft_sks: SerdeSecret(netinf.secret_key_share().unwrap().clone()),
                    hbbft_pk_set: netinf.public_key_set().clone(),
                    wallet: wallet_server_cfg[&id].clone(),
                    mint: mint_server_cfg[&id].clone(),
                    ln: ln_server_cfg[&id].clone(),
                    fee_consensus: fee_consensus.clone(),
                };
                (id, config)
            })
            .collect();

        let client_config = ClientConfig {
            max_evil,
            api_endpoints: peers
                .iter()
                .map(|&peer| format!("ws://127.0.0.1:{}", params.api_base_port + u16::from(peer)))
                .collect(),
            mint: mint_client_cfg,
            wallet: wallet_client_cfg,
            ln: ln_client_cfg,
            fee_consensus,
        };

        (server_config, client_config)
    }

    async fn distributed_gen(
        connections: &mut AnyPeerConnections<Self::ConfigMessage>,
        our_id: &PeerId,
        peers: &[PeerId],
        max_evil: usize,
        params: &mut Self::Params,
        mut rng: impl RngCore + CryptoRng,
    ) -> Result<(Self, Self::ClientConfig), Self::ConfigError> {
        let (params, remote) = match params {
            (params, Some(remote_cfg)) => (params, remote_cfg),
            _ => panic!("Remote server configs need to be passed in distributed config gen"),
        };

        // HBBFT threshold key generation
        // TODO should probably refactor to a shared threshold crypto module
        let (sk, pk) = LightningModuleConfig::distributed_threshold_gen(
            connections,
            our_id,
            peers,
            max_evil,
            &mut rng,
        )
        .await;

        let wallet = &mut remote.wallet;
        let (wsc, wcc) =
            WalletConfig::distributed_gen(wallet, our_id, peers, max_evil, &mut (), &mut rng)
                .await
                .unwrap();

        let ln = &mut remote.lightning;
        let (ln_server_cfg, ln_client_cfg) =
            LightningModuleConfig::distributed_gen(ln, our_id, peers, max_evil, &mut (), &mut rng)
                .await
                .unwrap();

        let cfg_peers = peers
            .iter()
            .map(|id| {
                let id_u16: u16 = (*id).into();
                let address = remote.hbbft.peers.get(id).unwrap();
                let tls_cert = remote.tls.peer_certs.get(id).unwrap().clone();
                // FIXME replace with proper port configuration
                let base_address = address.addr.split(':').next().unwrap();
                let peer = Peer {
                    connection: ConnectionConfig {
                        addr: format!("{}:{}", base_address, (params.hbbft_base_port + id_u16)),
                    },
                    tls_cert,
                };

                (*id, peer)
            })
            .collect::<BTreeMap<_, _>>();

        let fee_consensus = FeeConsensus {
            fee_coin_spend_abs: minimint_api::Amount::ZERO,
            fee_peg_in_abs: minimint_api::Amount::ZERO,
            fee_coin_issuance_abs: minimint_api::Amount::ZERO,
            fee_peg_out_abs: minimint_api::Amount::ZERO,
            fee_contract_input: minimint_api::Amount::ZERO,
            fee_contract_output: minimint_api::Amount::ZERO,
        };

        let id_u16: u16 = (*our_id).into();
        let config = ServerConfig {
            identity: *our_id,
            hbbft_bind_addr: format!("127.0.0.1:{}", params.hbbft_base_port + id_u16),
            api_bind_addr: format!("127.0.0.1:{}", params.api_base_port + id_u16),
            tls_cert: remote.tls.our_certificate.clone(),
            tls_key: remote.tls.our_private_key.clone(),
            peers: cfg_peers,
            hbbft_sks: SerdeSecret(SecretKeyShare::from_mut(&mut sk.clone())),
            hbbft_pk_set: pk.clone(),
            wallet: wsc,
            mint: remote.configs.0.clone(),
            ln: ln_server_cfg,
            fee_consensus: fee_consensus.clone(),
        };

        let client_config = ClientConfig {
            max_evil,
            api_endpoints: peers
                .iter()
                .map(|&peer| format!("ws://127.0.0.1:{}", params.api_base_port + u16::from(peer)))
                .collect(),
            mint: remote.configs.1.clone(),
            wallet: wcc,
            ln: ln_client_cfg,
            fee_consensus,
        };

        Ok((config, client_config))
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
}

pub async fn gen_connections<T>(
    base_port: u16,
    our_id: &PeerId,
    peers: &[PeerId],
    certs: TlsConfig,
) -> AnyPeerConnections<T>
where
    T: std::fmt::Debug + Clone + Serialize + DeserializeOwned + Unpin + Send + Sync + 'static,
{
    let connector = TlsTcpConnector::new(certs).to_any();
    let network = gen_local_network_config(base_port, our_id, peers);
    ReconnectPeerConnections::new(network, connector)
        .await
        .to_any()
}

pub fn gen_tls_configs(peers: &[PeerId]) -> HashMap<PeerId, TlsConfig> {
    let keys: HashMap<PeerId, (rustls::Certificate, rustls::PrivateKey)> = peers
        .iter()
        .map(|peer| {
            let (cert, key) = gen_cert_and_key(&format!("peer-{}", peer.to_usize())).unwrap();
            (*peer, (cert, key))
        })
        .collect::<HashMap<_, _>>();
    let certs: HashMap<PeerId, rustls::Certificate> = keys
        .iter()
        .map(|(peer, (cert, _))| (*peer, cert.clone()))
        .collect::<HashMap<_, _>>();
    keys.iter()
        .map(|(peer, (cert, key))| {
            (
                *peer,
                TlsConfig {
                    our_certificate: cert.clone(),
                    our_private_key: key.clone(),
                    peer_certs: certs.clone(),
                },
            )
        })
        .collect::<HashMap<_, _>>()
}

pub fn gen_local_network_config(
    base_port: u16,
    our_id: &PeerId,
    peers: &[PeerId],
) -> NetworkConfig {
    NetworkConfig {
        identity: *our_id,
        bind_addr: format!("127.0.0.1:{}", base_port + u16::from(*our_id)),
        peers: peers
            .iter()
            .map(|&id| {
                (
                    id,
                    ConnectionConfig {
                        addr: format!("127.0.0.1:{}", base_port + u16::from(id)),
                    },
                )
            })
            .collect(),
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
