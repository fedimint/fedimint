use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, ensure};
use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_core::config::PeerUrl;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::util::SafeUrl;
use fedimint_server_core::dashboard_ui::ConnectionType;
use rustls::pki_types::ServerName;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream, rustls};
use tokio_util::codec::LengthDelimitedCodec;

use super::IP2PConnector;
use super::iroh::parse_p2p;
use crate::net::p2p_connection::{DynP2PConnection, IP2PConnection as _};

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub private_key: Arc<rustls::pki_types::PrivateKeyDer<'static>>,
    pub certificates: BTreeMap<PeerId, rustls::pki_types::CertificateDer<'static>>,
    pub peer_names: BTreeMap<PeerId, String>,
}

/// TCP connector with encryption and authentication
pub struct TlsTcpConnector {
    pub(crate) cfg: TlsConfig,
    pub(crate) peers: BTreeMap<PeerId, SafeUrl>,
    pub(crate) identity: PeerId,
    pub(crate) listener: TcpListener,
    pub(crate) acceptor: TlsAcceptor,
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
                .add(cert.clone())
                .expect("Could not add peer certificate");
        }

        let verifier = WebPkiClientVerifier::builder(root_cert_store.into())
            .build()
            .expect("Failed to create client verifier");

        let certificate = cfg
            .certificates
            .get(&identity)
            .expect("No certificate for ourself found")
            .clone();

        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![certificate], cfg.private_key.clone_key())
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
                .add(cert.clone())
                .expect("Could not add peer certificate");
        }

        let certificate = self
            .cfg
            .certificates
            .get(&self.identity)
            .expect("No certificate for ourself found")
            .clone();

        let cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_client_auth_cert(vec![certificate], self.cfg.private_key.clone_key())
            .expect("Failed to create TLS config");

        let domain = ServerName::try_from(dns_sanitize(&self.cfg.peer_names[&peer]))
            .expect("Always a valid DNS name");

        let destination = self.peers.get(&peer).expect("No url for peer");

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

    fn connection_type(&self, _peer: PeerId) -> Option<ConnectionType> {
        // TLS connections are always direct
        Some(ConnectionType::Direct)
    }
}

pub fn gen_cert_and_key(
    name: &str,
) -> Result<
    (
        rustls::pki_types::CertificateDer<'static>,
        Arc<rustls::pki_types::PrivateKeyDer<'static>>,
    ),
    anyhow::Error,
> {
    let cert_key = rcgen::generate_simple_self_signed(vec![dns_sanitize(name)])?;

    Ok((
        rustls::pki_types::CertificateDer::from(cert_key.cert.der().to_vec()),
        Arc::new(
            rustls::pki_types::PrivateKeyDer::try_from(cert_key.key_pair.serialize_der())
                .expect("Failed to create private key"),
        ),
    ))
}

/// Sanitizes name as valid domain name
pub fn dns_sanitize(name: &str) -> String {
    format!(
        "peer{}",
        name.replace(|c: char| !c.is_ascii_alphanumeric(), "_")
    )
}
