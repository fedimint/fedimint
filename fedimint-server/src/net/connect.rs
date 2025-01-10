//! Provides an abstract network connection interface and multiple
//! implementations

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::format_err;
use async_trait::async_trait;
use fedimint_core::util::SafeUrl;
use fedimint_core::PeerId;
use futures::Stream;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::server::AllowAnyAuthenticatedClient;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::{rustls, TlsAcceptor, TlsConnector};

use crate::net::framed::{AnyFramedTransport, BidiFramed, FramedTransport};

/// Shared [`Connector`] trait object
pub type SharedAnyConnector<M> = Arc<dyn Connector<M> + Send + Sync + Unpin + 'static>;

/// Owned [`Connector`] trait object
pub type AnyConnector<M> = Box<dyn Connector<M> + Send + Sync + Unpin + 'static>;

/// Result of a connection opening future
pub type ConnectResult<M> = Result<(PeerId, AnyFramedTransport<M>), anyhow::Error>;

/// Owned trait object type for incoming connection listeners
pub type ConnectionListener<M> =
    Pin<Box<dyn Stream<Item = ConnectResult<M>> + Send + Unpin + 'static>>;

/// Allows to connect to peers and to listen for incoming connections
///
/// Connections are message based ([`FramedTransport`]) and should be
/// authenticated and encrypted for production deployments.
#[async_trait]
pub trait Connector<M> {
    /// Connect to a `destination`
    async fn connect_framed(&self, destination: SafeUrl, peer: PeerId) -> ConnectResult<M>;

    /// Listen for incoming connections on `bind_addr`
    async fn listen(&self, bind_addr: SocketAddr) -> Result<ConnectionListener<M>, anyhow::Error>;

    /// Transform this concrete `Connector` into an owned trait object version
    /// of itself
    fn into_dyn(self) -> AnyConnector<M>
    where
        Self: Sized + Send + Sync + Unpin + 'static,
    {
        Box::new(self)
    }
}

/// TCP connector with encryption and authentication
#[derive(Debug)]
pub struct TlsTcpConnector {
    our_certificate: rustls::Certificate,
    our_private_key: rustls::PrivateKey,
    peer_certs: Arc<PeerCertStore>,
    /// Copy of the certs from `peer_certs`, but in a format that `tokio_rustls`
    /// understands
    cert_store: RootCertStore,
    peer_names: BTreeMap<PeerId, String>,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub our_private_key: rustls::PrivateKey,
    pub peer_certs: BTreeMap<PeerId, rustls::Certificate>,
    pub peer_names: BTreeMap<PeerId, String>,
}

#[derive(Debug, Clone)]
pub struct PeerCertStore {
    peer_certificates: Vec<(PeerId, rustls::Certificate)>,
}

impl TlsTcpConnector {
    pub fn new(cfg: TlsConfig, our_id: PeerId) -> TlsTcpConnector {
        let mut cert_store = RootCertStore::empty();
        for cert in cfg.peer_certs.values() {
            cert_store
                .add(cert)
                .expect("Could not add peer certificate");
        }

        TlsTcpConnector {
            our_certificate: cfg.peer_certs.get(&our_id).expect("exists").clone(),
            our_private_key: cfg.our_private_key,
            peer_certs: Arc::new(PeerCertStore::new(cfg.peer_certs)),
            cert_store,
            peer_names: cfg.peer_names,
        }
    }
}

impl PeerCertStore {
    fn new(certs: impl IntoIterator<Item = (PeerId, rustls::Certificate)>) -> PeerCertStore {
        PeerCertStore {
            peer_certificates: certs.into_iter().collect(),
        }
    }

    fn get_peer_by_cert(&self, cert: &rustls::Certificate) -> Option<PeerId> {
        self.peer_certificates
            .iter()
            .find_map(|(peer, peer_cert)| if peer_cert == cert { Some(*peer) } else { None })
    }

    fn authenticate_peer(
        &self,
        received: Option<&[rustls::Certificate]>,
    ) -> Result<PeerId, anyhow::Error> {
        let cert_chain =
            received.ok_or_else(|| anyhow::anyhow!("Peer did not authenticate itself"))?;

        if cert_chain.len() != 1 {
            return Err(anyhow::anyhow!(
                "Received certificate chain of len={}, expected=1",
                cert_chain.len()
            ));
        }

        let received_cert = cert_chain.first().expect("Checked above");

        self.get_peer_by_cert(received_cert)
            .ok_or_else(|| anyhow::anyhow!("Unknown certificate"))
    }

    async fn accept_connection<M>(
        &self,
        listener: &mut TcpListener,
        acceptor: &TlsAcceptor,
    ) -> Result<(PeerId, AnyFramedTransport<M>), anyhow::Error>
    where
        M: Debug + serde::Serialize + serde::de::DeserializeOwned + Send + Unpin + 'static,
    {
        let (connection, _) = listener.accept().await?;
        let tls_conn = acceptor.accept(connection).await?;

        let (_, tls_session) = tls_conn.get_ref();
        let auth_peer = self.authenticate_peer(tls_session.peer_certificates())?;

        let framed = BidiFramed::new(tokio_rustls::TlsStream::Server(tls_conn)).into_dyn();
        Ok((auth_peer, framed))
    }
}

#[async_trait]
impl<M> Connector<M> for TlsTcpConnector
where
    M: Debug + serde::Serialize + serde::de::DeserializeOwned + Send + Unpin + 'static,
{
    async fn connect_framed(&self, destination: SafeUrl, peer: PeerId) -> ConnectResult<M> {
        let cfg = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(self.cert_store.clone())
            .with_client_auth_cert(
                vec![self.our_certificate.clone()],
                self.our_private_key.clone(),
            )
            .expect("Failed to create TLS config");

        let fake_domain =
            rustls::ServerName::try_from(dns_sanitize(&self.peer_names[&peer]).as_str())
                .expect("Always a valid DNS name");

        let connector = TlsConnector::from(Arc::new(cfg));
        let tls_conn = connector
            .connect(
                fake_domain,
                TcpStream::connect(parse_host_port(&destination)?).await?,
            )
            .await?;

        let (_, tls_session) = tls_conn.get_ref();
        let auth_peer = self
            .peer_certs
            .authenticate_peer(tls_session.peer_certificates())?;

        if auth_peer != peer {
            return Err(anyhow::anyhow!("Connected to unexpected peer"));
        }

        let framed = BidiFramed::new(tokio_rustls::TlsStream::Client(tls_conn)).into_dyn();

        Ok((peer, framed))
    }

    async fn listen(&self, bind_addr: SocketAddr) -> Result<ConnectionListener<M>, anyhow::Error> {
        let verifier = AllowAnyAuthenticatedClient::new(self.cert_store.clone());
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(Arc::from(verifier))
            .with_single_cert(
                vec![self.our_certificate.clone()],
                self.our_private_key.clone(),
            )
            .unwrap();
        let listener = TcpListener::bind(bind_addr).await?;
        let peer_certs = self.peer_certs.clone();

        let stream = futures::stream::unfold(listener, move |mut listener| {
            let acceptor = TlsAcceptor::from(Arc::new(config.clone()));
            let peer_certs = peer_certs.clone();

            Box::pin(async move {
                let res = peer_certs.accept_connection(&mut listener, &acceptor).await;
                Some((res, listener))
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
