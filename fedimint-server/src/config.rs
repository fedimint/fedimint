use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use fedimint_api::config::BitcoindRpcCfg;
use fedimint_api::config::{DkgMessage, DkgRunner, GenerateConfig};
use fedimint_api::net::peers::AnyPeerConnections;
use fedimint_api::task::TaskGroup;
use fedimint_api::{Amount, NumPeers, PeerId};
pub use fedimint_core::config::*;
use fedimint_core::modules::ln::config::LightningModuleConfig;
use fedimint_core::modules::mint::config::MintConfig;
use fedimint_core::modules::wallet::config::WalletConfig;
use hbbft::crypto::serde_impl::SerdeSecret;
use rand::{CryptoRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use threshold_crypto::G1Projective;
use tokio_rustls::rustls;
use tracing::info;
use url::Url;

use crate::fedimint_api::net::peers::PeerConnections;
use crate::net::connect::Connector;
use crate::net::connect::TlsConfig;
use crate::net::peers::{ConnectionConfig, NetworkConfig};
use crate::{ReconnectPeerConnections, TlsTcpConnector};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub federation_name: String,
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
    pub hbbft: ConnectionConfig,
    #[serde(with = "serde_tls_cert")]
    pub tls_cert: rustls::Certificate,
    /// The peer's websocket network address and port (e.g. `ws://10.42.0.10:5000`)
    pub api_addr: Url,
    /// human-readable name
    pub name: String,
}

#[derive(Debug, Clone)]
/// network config for a server
pub struct ServerConfigParams {
    pub tls: TlsConfig,
    pub hbbft: NetworkConfig,
    pub api: NetworkConfig,
    pub server_dkg: NetworkConfig,
    pub wallet_dkg: NetworkConfig,
    pub lightning_dkg: NetworkConfig,
    pub mint_dkg: NetworkConfig,
    pub amount_tiers: Vec<Amount>,
    pub federation_name: String,
    pub bitcoind_rpc: String,
}

#[async_trait(?Send)]
impl GenerateConfig for ServerConfig {
    type Params = HashMap<PeerId, ServerConfigParams>;
    type ClientConfig = ClientConfig;
    type ConfigMessage = (KeyType, DkgMessage<G1Projective>);
    type ConfigError = ();

    fn trusted_dealer_gen(
        peers: &[PeerId],
        params: &Self::Params,
        mut rng: impl RngCore + CryptoRng,
    ) -> (BTreeMap<PeerId, Self>, Self::ClientConfig) {
        let netinfo = hbbft::NetworkInfo::generate_map(peers.to_vec(), &mut rng)
            .expect("Could not generate HBBFT netinfo");
        let epochinfo = hbbft::NetworkInfo::generate_map(peers.to_vec(), &mut rng)
            .expect("Could not generate HBBFT netinfo");

        let peer0 = &params[&PeerId::from(0)];
        let (wallet_server_cfg, wallet_client_cfg) = WalletConfig::trusted_dealer_gen(
            peers,
            &BitcoindRpcCfg {
                btc_rpc_address: peer0.bitcoind_rpc.clone(),
                btc_rpc_user: "bitcoin".into(),
                btc_rpc_pass: "bitcoin".into(),
            },
            &mut rng,
        );
        let (mint_server_cfg, mint_client_cfg) =
            MintConfig::trusted_dealer_gen(peers, &peer0.amount_tiers, &mut rng);
        let (ln_server_cfg, ln_client_cfg) =
            LightningModuleConfig::trusted_dealer_gen(peers, &(), &mut rng);

        let server_config = netinfo
            .iter()
            .map(|(&id, netinf)| {
                let epoch_keys = epochinfo.get(&id).unwrap();
                let config = ServerConfig {
                    federation_name: params[&id].federation_name.clone(),
                    identity: id,
                    hbbft_bind_addr: params[&id].hbbft.bind_addr.clone(),
                    api_bind_addr: params[&id].api.bind_addr.clone(),
                    tls_cert: params[&id].tls.our_certificate.clone(),
                    tls_key: params[&id].tls.our_private_key.clone(),
                    peers: params[&id].peers(),
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

        let names: HashMap<PeerId, String> = peers
            .iter()
            .map(|peer| (*peer, format!("peer-{}", peer.to_usize())))
            .collect();

        let client_config = ClientConfig {
            federation_name: peer0.federation_name.clone(),
            nodes: peer0.api.nodes("ws://", names),
            mint: mint_client_cfg,
            wallet: wallet_client_cfg,
            ln: ln_client_cfg,
        };

        (server_config, client_config)
    }

    fn to_client_config(&self) -> Self::ClientConfig {
        let nodes = self
            .peers
            .iter()
            .map(|(peer_id, peer)| Node {
                url: peer.api_addr.clone(),
                name: format!("node #{}", peer_id),
            })
            .collect();
        ClientConfig {
            federation_name: self.federation_name.clone(),
            nodes,
            mint: self.mint.to_client_config(),
            wallet: self.wallet.to_client_config(),
            ln: self.ln.to_client_config(),
        }
    }

    fn validate_config(&self, identity: &PeerId) {
        assert_eq!(
            self.epoch_sks.public_key_share(),
            self.epoch_pk_set.public_key_share(identity.to_usize()),
            "Epoch private key doesn't match pubkey share"
        );
        assert_eq!(
            self.hbbft_sks.public_key_share(),
            self.hbbft_pk_set.public_key_share(identity.to_usize()),
            "HBBFT private key doesn't match pubkey share"
        );
        assert_eq!(
            self.peers.keys().max().copied().map(|id| id.to_usize()),
            Some(self.peers.len() - 1),
            "Peer ids are not indexed from 0"
        );
        assert_eq!(
            self.peers.keys().min().copied(),
            Some(PeerId::from(0)),
            "Peer ids are not indexed from 0"
        );

        self.mint.validate_config(identity);
        self.ln.validate_config(identity);
        self.wallet.validate_config(identity);
    }

    async fn distributed_gen(
        connections: &mut AnyPeerConnections<Self::ConfigMessage>,
        our_id: &PeerId,
        peers: &[PeerId],
        params: &Self::Params,
        mut rng: impl RngCore + CryptoRng,
        task_group: &mut TaskGroup,
    ) -> Result<Option<(Self, Self::ClientConfig)>, Self::ConfigError> {
        // in case we are running by ourselves, avoid DKG
        if peers.len() == 1 {
            let (server, client) = Self::trusted_dealer_gen(peers, params, rng);
            return Ok(Some((server[our_id].clone(), client)));
        }
        info!("Peer {} running distributed key generation...", our_id);

        let params = params[our_id].clone();
        // hbbft uses a lower threshold of signing keys (f+1)
        let mut dkg = DkgRunner::new(KeyType::Hbbft, peers.one_honest(), our_id, peers);
        dkg.add(KeyType::Epoch, peers.threshold());

        // run DKG for epoch and hbbft keys
        let keys = if let Some(v) = dkg.run_g1(connections, &mut rng).await {
            v
        } else {
            return Ok(None);
        };
        let (hbbft_pks, hbbft_sks) = keys[&KeyType::Hbbft].threshold_crypto();
        let (epoch_pks, epoch_sks) = keys[&KeyType::Epoch].threshold_crypto();

        let mut wallet = connect(params.wallet_dkg.clone(), params.tls.clone(), task_group).await;
        let bitcoin = &BitcoindRpcCfg {
            btc_rpc_address: params.bitcoind_rpc.clone(),
            btc_rpc_user: "bitcoin".into(),
            btc_rpc_pass: "bitcoin".into(),
        };
        let (wallet_server_cfg, wallet_client_cfg) = if let Some(v) =
            WalletConfig::distributed_gen(&mut wallet, our_id, peers, bitcoin, &mut rng, task_group)
                .await
                .expect("wallet error")
        {
            v
        } else {
            return Ok(None);
        };

        let mut ln = connect(params.lightning_dkg.clone(), params.tls.clone(), task_group).await;
        let (ln_server_cfg, ln_client_cfg) = if let Some(v) =
            LightningModuleConfig::distributed_gen(
                &mut ln,
                our_id,
                peers,
                &(),
                &mut rng,
                task_group,
            )
            .await?
        {
            v
        } else {
            return Ok(None);
        };

        let mut mint = connect(params.mint_dkg.clone(), params.tls.clone(), task_group).await;
        let param = &params.amount_tiers;
        let (mint_server_cfg, mint_client_cfg) = if let Some(v) =
            MintConfig::distributed_gen(&mut mint, our_id, peers, param, &mut rng, task_group)
                .await?
        {
            v
        } else {
            return Ok(None);
        };

        let server = ServerConfig {
            federation_name: params.federation_name.clone(),
            identity: *our_id,
            hbbft_bind_addr: params.hbbft.bind_addr.clone(),
            api_bind_addr: params.api.bind_addr.clone(),
            tls_cert: params.tls.our_certificate.clone(),
            tls_key: params.tls.our_private_key.clone(),
            peers: params.peers(),
            hbbft_sks: SerdeSecret(hbbft_sks),
            hbbft_pk_set: hbbft_pks,
            epoch_sks: SerdeSecret(epoch_sks),
            epoch_pk_set: epoch_pks,
            wallet: wallet_server_cfg,
            mint: mint_server_cfg,
            ln: ln_server_cfg,
        };

        let client = ClientConfig {
            federation_name: params.federation_name,
            nodes: params.api.nodes("ws://", params.tls.peer_names),
            mint: mint_client_cfg,
            wallet: wallet_client_cfg,
            ln: ln_client_cfg,
        };

        Ok(Some((server, client)))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum KeyType {
    Hbbft,
    Epoch,
}

impl ServerConfig {
    pub fn network_config(&self) -> NetworkConfig {
        NetworkConfig {
            identity: self.identity,
            bind_addr: self.hbbft_bind_addr.clone(),
            peers: self
                .peers
                .iter()
                .map(|(&id, peer)| (id, peer.hbbft.clone()))
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
            peer_names: self
                .peers
                .iter()
                .map(|(peer, cfg)| (*peer, cfg.name.to_string()))
                .collect(),
        }
    }

    pub fn get_incoming_count(&self) -> u16 {
        self.identity.into()
    }
}

pub struct PeerServerParams {
    pub cert: rustls::Certificate,
    pub address: String,
    pub base_port: u16,
    pub name: String,
}

impl ServerConfigParams {
    pub fn peers(&self) -> BTreeMap<PeerId, Peer> {
        self.hbbft
            .peers
            .iter()
            .map(|(peer, hbbft)| {
                (
                    *peer,
                    Peer {
                        name: self.tls.peer_names[peer].clone(),
                        hbbft: hbbft.clone(),
                        tls_cert: self.tls.peer_certs[peer].clone(),
                        api_addr: Url::parse(&format!("ws://{}", self.api.peers[peer].address))
                            .expect("Could not parse URL"),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>()
    }

    pub fn gen_params(
        key: rustls::PrivateKey,
        our_id: PeerId,
        amount_tiers: Vec<Amount>,
        peers: &BTreeMap<PeerId, PeerServerParams>,
        federation_name: String,
        bitcoind_rpc: String,
    ) -> ServerConfigParams {
        let peer_certs: HashMap<PeerId, rustls::Certificate> = peers
            .iter()
            .map(|(peer, params)| (*peer, params.cert.clone()))
            .collect::<HashMap<_, _>>();

        let peer_names: HashMap<PeerId, String> = peers
            .iter()
            .map(|(peer, params)| (*peer, params.name.to_string()))
            .collect::<HashMap<_, _>>();

        let tls = TlsConfig {
            our_certificate: peers[&our_id].cert.clone(),
            our_private_key: key,
            peer_certs,
            peer_names,
        };

        ServerConfigParams {
            tls,
            hbbft: Self::gen_network(&our_id, 0, peers),
            api: Self::gen_network(&our_id, 1, peers),
            server_dkg: Self::gen_network(&our_id, 2, peers),
            wallet_dkg: Self::gen_network(&our_id, 3, peers),
            lightning_dkg: Self::gen_network(&our_id, 4, peers),
            mint_dkg: Self::gen_network(&our_id, 5, peers),
            amount_tiers,
            federation_name,
            bitcoind_rpc,
        }
    }

    fn gen_network(
        our_id: &PeerId,
        offset: u16,
        peers: &BTreeMap<PeerId, PeerServerParams>,
    ) -> NetworkConfig {
        NetworkConfig {
            identity: *our_id,
            bind_addr: format!(
                "{}:{}",
                peers[our_id].address,
                peers[our_id].base_port + offset
            ),
            peers: peers
                .iter()
                .map(|(peer, params)| {
                    let connection = ConnectionConfig {
                        address: format!("{}:{}", params.address, params.base_port + offset),
                    };
                    (*peer, connection)
                })
                .collect(),
        }
    }

    /// config for servers running on different ports on a local network
    pub fn gen_local(
        peers: &[PeerId],
        amount_tiers: Vec<Amount>,
        base_port: u16,
        federation_name: &str,
        bitcoind_rpc: &str,
    ) -> HashMap<PeerId, ServerConfigParams> {
        let keys: HashMap<PeerId, (rustls::Certificate, rustls::PrivateKey)> = peers
            .iter()
            .map(|peer| {
                let (cert, key) = gen_cert_and_key(&format!("peer-{}", peer.to_usize())).unwrap();
                (*peer, (cert, key))
            })
            .collect::<HashMap<_, _>>();

        let peer_params: BTreeMap<PeerId, PeerServerParams> = peers
            .iter()
            .map(|peer| {
                let params: PeerServerParams = PeerServerParams {
                    cert: keys[peer].0.clone(),
                    address: "127.0.0.1".to_string(),
                    base_port: base_port + (u16::from(*peer) * 6),
                    name: format!("peer-{}", peer.to_usize()),
                };
                (*peer, params)
            })
            .collect();

        peers
            .iter()
            .map(|peer| {
                let params: ServerConfigParams = Self::gen_params(
                    keys[peer].1.clone(),
                    *peer,
                    amount_tiers.clone(),
                    &peer_params,
                    federation_name.to_string(),
                    bitcoind_rpc.to_string(),
                );
                (*peer, params)
            })
            .collect()
    }
}

pub async fn connect<T>(
    network: NetworkConfig,
    certs: TlsConfig,
    task_group: &mut TaskGroup,
) -> AnyPeerConnections<T>
where
    T: std::fmt::Debug + Clone + Serialize + DeserializeOwned + Unpin + Send + Sync + 'static,
{
    let connector = TlsTcpConnector::new(certs).into_dyn();
    ReconnectPeerConnections::new(network, connector, task_group)
        .await
        .into_dyn()
}

pub fn gen_cert_and_key(
    name: &str,
) -> Result<(rustls::Certificate, rustls::PrivateKey), anyhow::Error> {
    let keypair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let keypair_ser = keypair.serialize_der();
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]);

    params.key_pair = Some(keypair);
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.is_ca = rcgen::IsCa::NoCa;
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
    use std::borrow::Cow;

    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
    use std::borrow::Cow;

    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
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
