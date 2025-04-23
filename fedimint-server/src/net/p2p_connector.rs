//! Provides an abstract network connector interface and multiple
//! implementations

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, ensure};
use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_core::config::PeerUrl;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::net::STANDARD_FEDIMINT_P2P_PORT;
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_NET_IROH;
use iroh::{Endpoint, NodeId, SecretKey};
use rustls::ServerName;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::server::AllowAnyAuthenticatedClient;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream, rustls};
use tokio_util::codec::LengthDelimitedCodec;
use tracing::info;

use crate::net::p2p_connection::{DynP2PConnection, IP2PConnection};

pub type DynP2PConnector<M> = Arc<dyn IP2PConnector<M>>;

/// Allows to connect to peers and to listen for incoming connections.
/// Connections are message based and should be authenticated and encrypted for
/// production deployments.
#[async_trait]
pub trait IP2PConnector<M>: Send + Sync + 'static {
    fn peers(&self) -> Vec<PeerId>;

    async fn connect(&self, peer: PeerId) -> anyhow::Result<DynP2PConnection<M>>;

    async fn accept(&self) -> anyhow::Result<(PeerId, DynP2PConnection<M>)>;

    fn into_dyn(self) -> DynP2PConnector<M>
    where
        Self: Sized,
    {
        Arc::new(self)
    }
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub private_key: rustls::PrivateKey,
    pub certificates: BTreeMap<PeerId, rustls::Certificate>,
    pub peer_names: BTreeMap<PeerId, String>,
}

/// TCP connector with encryption and authentication
pub struct TlsTcpConnector {
    cfg: TlsConfig,
    peers: BTreeMap<PeerId, SafeUrl>,
    identity: PeerId,
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsTcpConnector {
    pub async fn new(
        cfg: TlsConfig,
        p2p_bind_addr: SocketAddr,
        peers: BTreeMap<PeerId, PeerUrl>,
        identity: PeerId,
    ) -> TlsTcpConnector {
        let mut root_cert_store = RootCertStore::empty();

        for cert in cfg.certificates.values() {
            root_cert_store
                .add(cert)
                .expect("Could not add peer certificate");
        }

        let verifier = AllowAnyAuthenticatedClient::new(root_cert_store);

        let certificate = cfg
            .certificates
            .get(&identity)
            .expect("No certificate for ourself found")
            .clone();

        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::from(verifier))
            .with_single_cert(vec![certificate], cfg.private_key.clone())
            .expect("Failed to create TLS config");

        let listener = TcpListener::bind(p2p_bind_addr)
            .await
            .expect("Could not bind to port");

        let acceptor = TlsAcceptor::from(Arc::new(config.clone()));

        TlsTcpConnector {
            cfg,
            peers: peers.into_iter().map(|(id, peer)| (id, peer.url)).collect(),
            identity,
            listener,
            acceptor,
        }
    }
}

#[async_trait]
impl<M> IP2PConnector<M> for TlsTcpConnector
where
    M: Encodable + Decodable + Serialize + DeserializeOwned + Send + 'static,
{
    fn peers(&self) -> Vec<PeerId> {
        self.peers
            .keys()
            .filter(|peer| **peer != self.identity)
            .copied()
            .collect()
    }

    async fn connect(&self, peer: PeerId) -> anyhow::Result<DynP2PConnection<M>> {
        let mut root_cert_store = RootCertStore::empty();

        for cert in self.cfg.certificates.values() {
            root_cert_store
                .add(cert)
                .expect("Could not add peer certificate");
        }

        let certificate = self
            .cfg
            .certificates
            .get(&self.identity)
            .expect("No certificate for ourself found")
            .clone();

        let cfg = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_cert_store)
            .with_client_auth_cert(vec![certificate], self.cfg.private_key.clone())
            .expect("Failed to create TLS config");

        let domain = ServerName::try_from(dns_sanitize(&self.cfg.peer_names[&peer]).as_str())
            .expect("Always a valid DNS name");

        let destination = self.peers.get(&peer).expect("No url for peer {peer}");

        let tls = TlsConnector::from(Arc::new(cfg))
            .connect(domain, TcpStream::connect(parse_p2p(destination)?).await?)
            .await?;

        let certificate = tls
            .get_ref()
            .1
            .peer_certificates()
            .context("Peer did not authenticate itself")?
            .first()
            .context("Received certificate chain of length zero")?;

        let auth_peer = self
            .cfg
            .certificates
            .iter()
            .find_map(|(peer, c)| if c == certificate { Some(*peer) } else { None })
            .context("Unknown certificate")?;

        ensure!(auth_peer == peer, "Connected to unexpected peer");

        let framed = LengthDelimitedCodec::builder()
            .length_field_type::<u64>()
            .new_framed(TlsStream::Client(tls));

        Ok(framed.into_dyn())
    }

    async fn accept(&self) -> anyhow::Result<(PeerId, DynP2PConnection<M>)> {
        let tls = self
            .acceptor
            .accept(self.listener.accept().await?.0)
            .await?;

        let certificate = tls
            .get_ref()
            .1
            .peer_certificates()
            .context("Peer did not authenticate itself")?
            .first()
            .context("Received certificate chain of length zero")?;

        let auth_peer = self
            .cfg
            .certificates
            .iter()
            .find_map(|(peer, c)| if c == certificate { Some(*peer) } else { None })
            .context("Unknown certificate")?;

        let framed = LengthDelimitedCodec::builder()
            .length_field_type::<u64>()
            .new_framed(TlsStream::Server(tls));

        Ok((auth_peer, framed.into_dyn()))
    }
}

pub fn gen_cert_and_key(
    name: &str,
) -> Result<(rustls::Certificate, rustls::PrivateKey), anyhow::Error> {
    let cert_key = rcgen::generate_simple_self_signed(vec![dns_sanitize(name)])?;

    Ok((
        rustls::Certificate(cert_key.cert.der().to_vec()),
        rustls::PrivateKey(cert_key.key_pair.serialize_der()),
    ))
}

/// Sanitizes name as valid domain name
pub fn dns_sanitize(name: &str) -> String {
    format!(
        "peer{}",
        name.replace(|c: char| !c.is_ascii_alphanumeric(), "_")
    )
}

/// Parses the host and port from a url
pub fn parse_p2p(url: &SafeUrl) -> anyhow::Result<String> {
    ensure!(url.scheme() == "fedimint", "p2p url has invalid scheme");

    let host = url.host_str().context("p2p url is missing host")?;

    let port = url.port().unwrap_or(STANDARD_FEDIMINT_P2P_PORT);

    Ok(format!("{host}:{port}"))
}

#[derive(Debug, Clone)]
pub struct IrohConnector {
    /// Map of all peers' connection information we want to be connected to
    pub node_ids: BTreeMap<PeerId, NodeId>,
    /// The Iroh endpoint
    pub endpoint: Endpoint,
}

const FEDIMINT_P2P_ALPN: &[u8] = b"FEDIMINT_P2P_ALPN";

impl IrohConnector {
    pub async fn new(
        secret_key: SecretKey,
        p2p_bind_addr: SocketAddr,
        node_ids: BTreeMap<PeerId, NodeId>,
    ) -> Self {
        let identity = *node_ids
            .iter()
            .find(|entry| entry.1 == &secret_key.public())
            .expect("Our public key is not part of the keyset")
            .0;

        let builder = Endpoint::builder()
            .discovery_n0()
            .discovery_dht()
            .secret_key(secret_key)
            .alpns(vec![FEDIMINT_P2P_ALPN.to_vec()]);

        let builder = match p2p_bind_addr {
            SocketAddr::V4(addr_v4) => builder.bind_addr_v4(addr_v4),
            SocketAddr::V6(addr_v6) => builder.bind_addr_v6(addr_v6),
        };

        let endpoint = builder.bind().await.expect("Could not bind to port");

        info!(
            target: LOG_NET_IROH,
            %p2p_bind_addr,
            node_id = %endpoint.node_id(),
            node_id_pkarr = %z32::encode(endpoint.node_id().as_bytes()),
            "Iroh p2p server endpoint"
        );

        Self {
            node_ids: node_ids
                .into_iter()
                .filter(|entry| entry.0 != identity)
                .collect(),
            endpoint,
        }
    }
}

#[async_trait]
impl<M> IP2PConnector<M> for IrohConnector
where
    M: Encodable + Decodable + Serialize + DeserializeOwned + Send + 'static,
{
    fn peers(&self) -> Vec<PeerId> {
        self.node_ids.keys().copied().collect()
    }

    async fn connect(&self, peer: PeerId) -> anyhow::Result<DynP2PConnection<M>> {
        let node_id = *self
            .node_ids
            .get(&peer)
            .expect("No node id found for peer {peer}");

        let connection = self.endpoint.connect(node_id, FEDIMINT_P2P_ALPN).await?;

        Ok(connection.into_dyn())
    }

    async fn accept(&self) -> anyhow::Result<(PeerId, DynP2PConnection<M>)> {
        let connection = self
            .endpoint
            .accept()
            .await
            .context("Listener closed unexpectedly")?
            .accept()?
            .await?;

        let node_id = connection.remote_node_id()?;

        let auth_peer = self
            .node_ids
            .iter()
            .find(|entry| entry.1 == &node_id)
            .context("Node id {node_id} is unknown")?
            .0;

        Ok((*auth_peer, connection.into_dyn()))
    }
}
