//! Provides an abstract network connection interface and multiple
//! implementations

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{ensure, format_err, Context};
use async_trait::async_trait;
use fedimint_core::util::SafeUrl;
use fedimint_core::PeerId;
use futures::Stream;
use iroh::endpoint::Incoming;
use iroh::{Endpoint, NodeId, SecretKey};
use rustls::ServerName;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::server::AllowAnyAuthenticatedClient;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::{rustls, TlsAcceptor, TlsConnector, TlsStream};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;

use super::p2p_connection::IrohConnection;
use crate::net::p2p_connection::{DynP2PConnection, FramedTlsTcpStream, P2PConnection};

pub type DynP2PConnector<M> = Arc<dyn P2PConnector<M>>;

pub type P2PConnectionResult<M> = anyhow::Result<(PeerId, DynP2PConnection<M>)>;

pub type P2PConnectionListener<M> = Pin<Box<dyn Stream<Item = P2PConnectionResult<M>> + Send>>;

/// Allows to connect to peers and to listen for incoming connections.
/// Connections are message based and should be authenticated and encrypted for
/// production deployments.
#[async_trait]
pub trait P2PConnector<M>: Send + Sync + 'static {
    fn peers(&self) -> Vec<PeerId>;

    async fn connect(&self, peer: PeerId) -> anyhow::Result<DynP2PConnection<M>>;

    async fn listen(&self) -> anyhow::Result<P2PConnectionListener<M>>;

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
#[derive(Debug)]
pub struct TlsTcpConnector {
    cfg: TlsConfig,
    p2p_bind_addr: SocketAddr,
    peers: BTreeMap<PeerId, SafeUrl>,
    identity: PeerId,
}

impl TlsTcpConnector {
    pub fn new(
        cfg: TlsConfig,
        p2p_bind_addr: SocketAddr,
        peers: BTreeMap<PeerId, SafeUrl>,
        identity: PeerId,
    ) -> TlsTcpConnector {
        TlsTcpConnector {
            cfg,
            p2p_bind_addr,
            peers,
            identity,
        }
    }
}

#[async_trait]
impl<M> P2PConnector<M> for TlsTcpConnector
where
    M: Serialize + DeserializeOwned + Send + 'static,
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

        let destination = self
            .peers
            .get(&peer)
            .expect("No url for peer {peer}")
            .with_port_or_known_default();

        let tls = TlsConnector::from(Arc::new(cfg))
            .connect(
                domain,
                TcpStream::connect(parse_host_port(&destination)?).await?,
            )
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

        Ok(FramedTlsTcpStream::new(TlsStream::Client(tls)).into_dyn())
    }

    async fn listen(&self) -> anyhow::Result<P2PConnectionListener<M>> {
        let mut root_cert_store = RootCertStore::empty();

        for cert in self.cfg.certificates.values() {
            root_cert_store
                .add(cert)
                .expect("Could not add peer certificate");
        }

        let verifier = AllowAnyAuthenticatedClient::new(root_cert_store);

        let certificate = self
            .cfg
            .certificates
            .get(&self.identity)
            .expect("No certificate for ourself found")
            .clone();

        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::from(verifier))
            .with_single_cert(vec![certificate], self.cfg.private_key.clone())
            .expect("Failed to create TLS config");

        let listener = TcpListener::bind(self.p2p_bind_addr).await?;

        let acceptor = TlsAcceptor::from(Arc::new(config.clone()));

        let cfg = self.cfg.clone();

        let stream = TcpListenerStream::new(listener).then(move |connection| {
            Box::pin({
                let cfg = cfg.clone();
                let acceptor = acceptor.clone();

                async move {
                    let tls = acceptor.accept(connection?).await?;

                    let certificate = tls
                        .get_ref()
                        .1
                        .peer_certificates()
                        .context("Peer did not authenticate itself")?
                        .first()
                        .context("Received certificate chain of length zero")?;

                    let auth_peer = cfg
                        .certificates
                        .iter()
                        .find_map(|(peer, c)| if c == certificate { Some(*peer) } else { None })
                        .context("Unknown certificate")?;

                    let framed = FramedTlsTcpStream::new(TlsStream::Server(tls)).into_dyn();

                    Ok((auth_peer, framed))
                }
            })
        });

        Ok(Box::pin(stream))
    }
}

/// Sanitizes name as valid domain name
pub fn dns_sanitize(name: &str) -> String {
    let sanitized = name.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
    format!("peer{sanitized}")
}

/// Parses the host and port from a url
pub fn parse_host_port(url: &SafeUrl) -> anyhow::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| format_err!("Missing host in {url}"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| format_err!("Missing port in {url}"))?;

    Ok(format!("{host}:{port}"))
}

#[derive(Debug, Clone)]
pub struct IrohConnector {
    /// Our federation member's identity
    pub identity: PeerId,
    /// The secret key for our own Iroh Endpoint
    pub secret_key: SecretKey,
    /// Map of all peers' connection information we want to be connected to
    pub node_ids: BTreeMap<PeerId, NodeId>,
    /// The Iroh endpoint
    pub endpoint: Endpoint,
}

const FEDIMINT_ALPN: &[u8] = "FEDIMINT_ALPN".as_bytes();

impl IrohConnector {
    pub async fn new(
        secret_key: SecretKey,
        node_ids: BTreeMap<PeerId, NodeId>,
    ) -> anyhow::Result<Self> {
        let identity = *node_ids
            .iter()
            .find(|entry| entry.1 == &secret_key.public())
            .expect("Our public key is not part of the keyset")
            .0;

        Ok(Self {
            identity,
            secret_key: secret_key.clone(),
            node_ids: node_ids
                .into_iter()
                .filter(|entry| entry.0 != identity)
                .collect(),
            endpoint: Endpoint::builder()
                .discovery_n0()
                .secret_key(secret_key)
                .alpns(vec![FEDIMINT_ALPN.to_vec()])
                .bind()
                .await?,
        })
    }
}

#[async_trait]
impl<M> P2PConnector<M> for IrohConnector
where
    M: Serialize + DeserializeOwned + Send + 'static,
{
    fn peers(&self) -> Vec<PeerId> {
        self.node_ids.keys().copied().collect()
    }

    async fn connect(&self, peer: PeerId) -> anyhow::Result<DynP2PConnection<M>> {
        let node_id = *self
            .node_ids
            .get(&peer)
            .expect("No node id found for peer {peer}");

        let connection = self.endpoint.connect(node_id, FEDIMINT_ALPN).await?;

        Ok(IrohConnection::new(connection).into_dyn())
    }

    async fn listen(&self) -> anyhow::Result<P2PConnectionListener<M>> {
        let stream = futures::stream::unfold(self.clone(), move |endpoint| async move {
            let stream = endpoint.endpoint.accept().await?;

            let result = accept_connection(&endpoint.node_ids, stream).await;

            Some((result, endpoint))
        });

        Ok(Box::pin(stream))
    }
}

async fn accept_connection<M>(
    peers: &BTreeMap<PeerId, NodeId>,
    incoming: Incoming,
) -> P2PConnectionResult<M>
where
    M: Serialize + DeserializeOwned + Send + 'static,
{
    let connection = incoming.accept()?.await?;

    let node_id = iroh::endpoint::get_remote_node_id(&connection)?;

    let peer_id = peers
        .iter()
        .find(|entry| entry.1 == &node_id)
        .context("Node id {node_id} is unknown")?
        .0;

    let framed = IrohConnection::new(connection).into_dyn();

    Ok((*peer_id, framed))
}
