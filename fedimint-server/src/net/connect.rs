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
use rustls::ServerName;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::server::AllowAnyAuthenticatedClient;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::{rustls, TlsAcceptor, TlsConnector, TlsStream};
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::StreamExt;

use crate::net::framed::{DynFramedTransport, FramedTlsTcpStream, FramedTransport};

pub type DynConnector<M> = Arc<dyn Connector<M>>;

pub type ConnectResult<M> = anyhow::Result<(PeerId, DynFramedTransport<M>)>;

pub type ConnectionListener<M> = Pin<Box<dyn Stream<Item = ConnectResult<M>> + Send + 'static>>;

/// Allows to connect to peers and to listen for incoming connections.
/// Connections are message based and should be authenticated and encrypted for
/// production deployments.
#[async_trait]
pub trait Connector<M>: Send + Sync + 'static {
    fn peers(&self) -> Vec<PeerId>;

    async fn connect(&self, peer: PeerId) -> ConnectResult<M>;

    async fn listen(&self) -> anyhow::Result<ConnectionListener<M>>;

    fn into_dyn(self) -> DynConnector<M>
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
impl<M> Connector<M> for TlsTcpConnector
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

    async fn connect(&self, peer: PeerId) -> ConnectResult<M> {
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

        let framed = FramedTlsTcpStream::new(TlsStream::Client(tls)).into_dyn();

        Ok((peer, framed))
    }

    async fn listen(&self) -> anyhow::Result<ConnectionListener<M>> {
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
