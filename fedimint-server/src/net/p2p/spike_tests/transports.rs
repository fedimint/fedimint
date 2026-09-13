//! Old transport fixtures freeze empty TLS ALPN and legacy-only Iroh ALPN
//! from 46b195b5210908d43dd9276de236dbf1edc516e7. Framing and authenticated
//! identities are identical; no application-level capability message is sent.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, ensure};
use async_trait::async_trait;
use fedimint_core::PeerId;
use fedimint_core::config::PeerUrl;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::SafeUrl;
use fedimint_server_core::dashboard_ui::ConnectionType;
use iroh_next::endpoint::presets::Minimal;
use iroh_next::{Endpoint, EndpointAddr, RelayMode, TransportAddr};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream, rustls};
use tokio_util::codec::LengthDelimitedCodec;

use super::{TrackedConnector, Transport};
use crate::net::p2p_connection::{
    DynP2PConnection, IP2PConnection, MAX_P2P_MESSAGE_SIZE, TlsP2PConnection,
};
use crate::net::p2p_connector::{
    IP2PConnector, IrohConnector, TlsConfig, TlsTcpConnector, dns_sanitize, gen_cert_and_key,
    parse_p2p,
};

const OLD_ALPN: &[u8] = b"FEDIMINT_P2P_ALPN";
const DUAL_ALPN: &[u8] = b"FEDIMINT_P2P_DUAL_V1";

/// Actual old connector behavior, not a forced tag on negotiated dual traffic.
enum OldConnector {
    Tls(TlsTcpConnector),
    Iroh(IrohConnector),
}

#[async_trait]
impl IP2PConnector<Vec<u8>> for OldConnector {
    fn peers(&self) -> Vec<PeerId> {
        match self {
            Self::Tls(connector) => <TlsTcpConnector as IP2PConnector<Vec<u8>>>::peers(connector),
            Self::Iroh(connector) => <IrohConnector as IP2PConnector<Vec<u8>>>::peers(connector),
        }
    }

    async fn connect(&self, peer: PeerId) -> anyhow::Result<DynP2PConnection<Vec<u8>>> {
        match self {
            Self::Iroh(connector) => {
                let id = connector.endpoint_ids[&peer];
                let connection = connector
                    .endpoint
                    .connect(connector.connection_overrides[&id].clone(), OLD_ALPN)
                    .await?;
                Ok(connection.into_dyn())
            }
            Self::Tls(connector) => {
                // Frozen baseline client configuration: ALPN remains empty.
                let mut roots = rustls::RootCertStore::empty();
                for certificate in connector.cfg.certificates.values() {
                    roots.add(certificate.clone())?;
                }
                let config = rustls::ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_client_auth_cert(
                        vec![connector.cfg.certificates[&connector.identity].clone()],
                        connector.cfg.private_key.clone_key(),
                    )?;
                assert!(config.alpn_protocols.is_empty());
                let domain = ServerName::try_from(dns_sanitize(&connector.cfg.peer_names[&peer]))?;
                let stream = TlsConnector::from(Arc::new(config))
                    .connect(
                        domain,
                        TcpStream::connect(parse_p2p(&connector.peers[&peer])?).await?,
                    )
                    .await?;
                let certificate = stream
                    .get_ref()
                    .1
                    .peer_certificates()
                    .context("missing peer authentication")?
                    .first()
                    .context("empty certificate chain")?;
                ensure!(
                    certificate == &connector.cfg.certificates[&peer],
                    "wrong peer"
                );
                assert_eq!(stream.get_ref().1.alpn_protocol(), None);
                let framed = LengthDelimitedCodec::builder()
                    .length_field_type::<u64>()
                    .max_frame_length(MAX_P2P_MESSAGE_SIZE)
                    .new_framed(TlsStream::Client(stream));
                Ok(TlsP2PConnection::new(framed).into_dyn())
            }
        }
    }

    async fn accept(&self) -> anyhow::Result<(PeerId, DynP2PConnection<Vec<u8>>)> {
        // Accept framing/authentication did not change. Each underlying listener
        // below is configured exactly as the old listener, with no dual ALPN.
        match self {
            Self::Tls(connector) => connector.accept().await,
            Self::Iroh(connector) => connector.accept().await,
        }
    }

    fn connection_type(&self, _: PeerId) -> Option<ConnectionType> {
        Some(ConnectionType::Direct)
    }
}

pub(super) async fn pair(
    transport: Transport,
    new: [bool; 2],
) -> anyhow::Result<[Arc<TrackedConnector>; 2]> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    match transport {
        Transport::Tls => tls_pair(new, None).await,
        Transport::Iroh => iroh_pair(new).await,
    }
}

/// Byte-proxy controls used to retain a real TLS receive session without EOF.
#[derive(Default)]
pub(super) struct Blackhole {
    /// Request that the first established byte pipe stop forwarding.
    pub freeze: Notify,
    /// Acknowledge that neither direction is being forwarded.
    pub frozen: Notify,
    /// End the retained old TCP session.
    pub release: Notify,
}

/// Build dual TLS peers behind a controllable byte proxy for lower->higher.
pub(super) async fn blackhole_pair(
    tasks: &TaskGroup,
    control: Arc<Blackhole>,
) -> anyhow::Result<[Arc<TrackedConnector>; 2]> {
    tls_pair([true, true], Some((tasks, control))).await
}

async fn tls_pair(
    new: [bool; 2],
    proxy: Option<(&TaskGroup, Arc<Blackhole>)>,
) -> anyhow::Result<[Arc<TrackedConnector>; 2]> {
    let (cert_a, key_a) = gen_cert_and_key("a")?;
    let (cert_b, key_b) = gen_cert_and_key("b")?;
    let certificates = BTreeMap::from([(PeerId::from(0), cert_a), (PeerId::from(1), cert_b)]);
    let names = BTreeMap::from([
        (PeerId::from(0), "a".to_owned()),
        (PeerId::from(1), "b".to_owned()),
    ]);
    let cfg = |key| TlsConfig {
        private_key: key,
        certificates: certificates.clone(),
        peer_names: names.clone(),
    };
    let mut a = TlsTcpConnector::new(
        cfg(key_a),
        SocketAddr::from(([127, 0, 0, 1], 0)),
        BTreeMap::<PeerId, PeerUrl>::new(),
        PeerId::from(0),
    )
    .await;
    let mut b = TlsTcpConnector::new(
        cfg(key_b),
        SocketAddr::from(([127, 0, 0, 1], 0)),
        BTreeMap::<PeerId, PeerUrl>::new(),
        PeerId::from(1),
    )
    .await;
    a.peers.insert(
        PeerId::from(1),
        format!("fedimint://{}", b.listener.local_addr()?).parse::<SafeUrl>()?,
    );
    b.peers.insert(
        PeerId::from(0),
        format!("fedimint://{}", a.listener.local_addr()?).parse::<SafeUrl>()?,
    );
    if let Some((tasks, control)) = proxy {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        let target = b.listener.local_addr()?;
        a.peers.insert(
            PeerId::from(1),
            format!("fedimint://{}", listener.local_addr()?).parse()?,
        );
        let child_tasks = tasks.clone();
        tasks.spawn_cancellable("tls-blackhole-proxy", async move {
            let mut first = true;
            while let Ok((mut client, _)) = listener.accept().await {
                let mut server = TcpStream::connect(target).await.expect("test listener");
                let control = control.clone();
                let is_first = std::mem::replace(&mut first, false);
                child_tasks.spawn_cancellable("tls-blackhole-pipe", async move {
                    if is_first {
                        tokio::select! {
                            _ = tokio::io::copy_bidirectional(&mut client, &mut server) => return,
                            () = control.freeze.notified() => {}
                        }
                        // Keep the remote TCP socket open but stop forwarding
                        // bytes/EOF. This models a flow-control-alive path, not
                        // a transport error that the manager could observe.
                        control.frozen.notify_one();
                        control.release.notified().await;
                    } else {
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                    }
                });
            }
        });
    }
    let wrap = |mut connector: TlsTcpConnector, new| -> anyhow::Result<Arc<TrackedConnector>> {
        if new {
            return Ok(TrackedConnector::new(connector.into_dyn()));
        }
        // Frozen baseline server config: mutual certificates, empty ALPN.
        let mut roots = rustls::RootCertStore::empty();
        for certificate in connector.cfg.certificates.values() {
            roots.add(certificate.clone())?;
        }
        let verifier = WebPkiClientVerifier::builder(roots.into()).build()?;
        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![connector.cfg.certificates[&connector.identity].clone()],
                connector.cfg.private_key.clone_key(),
            )?;
        assert!(config.alpn_protocols.is_empty());
        connector.acceptor = TlsAcceptor::from(Arc::new(config));
        Ok(TrackedConnector::new(
            OldConnector::Tls(connector).into_dyn(),
        ))
    };
    Ok([wrap(a, new[0])?, wrap(b, new[1])?])
}

async fn iroh_pair(new: [bool; 2]) -> anyhow::Result<[Arc<TrackedConnector>; 2]> {
    // Real distinct QUIC connections on local UDP; disable discovery/relays so
    // these tests require neither Internet service nor environment overrides.
    let endpoint = |new| async move {
        Endpoint::builder(Minimal)
            .relay_mode(RelayMode::Disabled)
            .alpns(if new {
                vec![DUAL_ALPN.to_vec(), OLD_ALPN.to_vec()]
            } else {
                vec![OLD_ALPN.to_vec()]
            })
            .clear_ip_transports()
            .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))?
            .bind()
            .await
            .map_err(anyhow::Error::from)
    };
    let a = endpoint(new[0]).await?;
    let b = endpoint(new[1]).await?;
    let address = |endpoint: &Endpoint| {
        EndpointAddr::from_parts(
            endpoint.id(),
            endpoint.bound_sockets().into_iter().map(TransportAddr::Ip),
        )
    };
    let addr_a = address(&a);
    let addr_b = address(&b);
    let id_a = a.id();
    let id_b = b.id();
    let wrap = |endpoint, peer, id, address, new| {
        let connector = IrohConnector {
            endpoint,
            endpoint_ids: BTreeMap::from([(peer, id)]),
            connection_overrides: BTreeMap::from([(id, address)]),
        };
        TrackedConnector::new(if new {
            connector.into_dyn()
        } else {
            OldConnector::Iroh(connector).into_dyn()
        })
    };
    Ok([
        wrap(a, PeerId::from(1), id_b, addr_b, new[0]),
        wrap(b, PeerId::from(0), id_a, addr_a, new[1]),
    ])
}

#[tokio::test]
async fn dual_alpn_does_not_admit_unconfigured_tls_certificate() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (known, _) = gen_cert_and_key("known")?;
    let (server_cert, server_key) = gen_cert_and_key("server")?;
    let (unknown, unknown_key) = gen_cert_and_key("unknown")?;
    let names = BTreeMap::from([
        (PeerId::from(0), "unknown".to_owned()),
        (PeerId::from(1), "server".to_owned()),
    ]);
    let server = TlsTcpConnector::new(
        TlsConfig {
            private_key: server_key,
            certificates: BTreeMap::from([
                (PeerId::from(0), known),
                (PeerId::from(1), server_cert.clone()),
            ]),
            peer_names: names.clone(),
        },
        SocketAddr::from(([127, 0, 0, 1], 0)),
        BTreeMap::new(),
        PeerId::from(1),
    )
    .await;
    let mut client = TlsTcpConnector::new(
        TlsConfig {
            private_key: unknown_key,
            certificates: BTreeMap::from([
                (PeerId::from(0), unknown),
                (PeerId::from(1), server_cert),
            ]),
            peer_names: names,
        },
        SocketAddr::from(([127, 0, 0, 1], 0)),
        BTreeMap::new(),
        PeerId::from(0),
    )
    .await;
    client.peers.insert(
        PeerId::from(1),
        format!("fedimint://{}", server.listener.local_addr()?).parse()?,
    );
    let (_, accepted) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        tokio::join!(
            <TlsTcpConnector as IP2PConnector<Vec<u8>>>::connect(&client, PeerId::from(1)),
            <TlsTcpConnector as IP2PConnector<Vec<u8>>>::accept(&server),
        )
    })
    .await?;
    assert!(
        accepted.is_err(),
        "dual ALPN must not bypass certificate membership"
    );
    Ok(())
}

#[tokio::test]
async fn dual_alpn_does_not_admit_unconfigured_iroh_identity() -> anyhow::Result<()> {
    let server_endpoint = Endpoint::builder(Minimal)
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![DUAL_ALPN.to_vec()])
        .clear_ip_transports()
        .bind_addr(SocketAddr::from(([127, 0, 0, 1], 0)))?
        .bind()
        .await?;
    let remote = EndpointAddr::from_parts(
        server_endpoint.id(),
        server_endpoint
            .bound_sockets()
            .into_iter()
            .map(TransportAddr::Ip),
    );
    let server = IrohConnector {
        endpoint: server_endpoint,
        endpoint_ids: BTreeMap::new(),
        connection_overrides: BTreeMap::new(),
    };
    let client = Endpoint::builder(Minimal)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await?;
    let (_, accepted) = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        tokio::join!(
            client.connect(remote, DUAL_ALPN),
            <IrohConnector as IP2PConnector<Vec<u8>>>::accept(&server),
        )
    })
    .await?;
    assert!(
        accepted.is_err(),
        "dual ALPN must not bypass endpoint membership"
    );
    Ok(())
}
