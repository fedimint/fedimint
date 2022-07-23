//! Provides an abstract network connection interface and multiple implementations

use crate::net::framed::{AnyFramedTransport, BidiFramed, FramedTransport};
use async_trait::async_trait;
use fedimint_api::PeerId;
use futures::Stream;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::server::AllowAnyAuthenticatedClient;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::{rustls, TlsAcceptor, TlsConnector, TlsStream};

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
/// Connections are message based ([`FramedTransport`]) and should be authenticated and encrypted
/// for production deployments.
#[async_trait]
pub trait Connector<M> {
    /// Connect to a `destination`
    async fn connect_framed(&self, destination: String, peer: PeerId) -> ConnectResult<M>;

    /// Listen for incoming connections on `bind_addr`
    async fn listen(&self, bind_addr: String) -> Result<ConnectionListener<M>, anyhow::Error>;

    /// Transform this concrete `Connector` into an owned trait object version of itself
    fn to_any(self) -> AnyConnector<M>
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
    /// Copy of the certs from `peer_certs`, but in a format that `tokio_rustls` understands
    cert_store: RootCertStore,
}

#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub our_certificate: rustls::Certificate,
    pub our_private_key: rustls::PrivateKey,
    pub peer_certs: HashMap<PeerId, rustls::Certificate>,
}

#[derive(Debug, Clone)]
pub struct PeerCertStore {
    peer_certificates: Vec<(PeerId, rustls::Certificate)>,
}

impl TlsTcpConnector {
    pub fn new(cfg: TlsConfig) -> TlsTcpConnector {
        let mut cert_store = RootCertStore::empty();
        for (_, cert) in cfg.peer_certs.iter() {
            cert_store
                .add(cert)
                .expect("Could not add peer certificate");
        }

        TlsTcpConnector {
            our_certificate: cfg.our_certificate,
            our_private_key: cfg.our_private_key,
            peer_certs: Arc::new(PeerCertStore::new(cfg.peer_certs)),
            cert_store,
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

        let framed =
            BidiFramed::<_, WriteHalf<TlsStream<TcpStream>>, ReadHalf<TlsStream<TcpStream>>>::new(
                tls_conn,
            )
            .to_any();
        Ok((auth_peer, framed))
    }
}

#[async_trait]
impl<M> Connector<M> for TlsTcpConnector
where
    M: Debug + serde::Serialize + serde::de::DeserializeOwned + Send + Unpin + 'static,
{
    async fn connect_framed(&self, destination: String, peer: PeerId) -> ConnectResult<M> {
        let cfg = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(self.cert_store.clone())
            .with_single_cert(
                vec![self.our_certificate.clone()],
                self.our_private_key.clone(),
            )
            .expect("Failed to create TLS config");

        let fake_domain =
            rustls::ServerName::try_from(format!("peer-{}", peer.to_usize()).as_str())
                .expect("Always a valid DNS name");

        let connector = TlsConnector::from(Arc::new(cfg));
        let tls_conn = connector
            .connect(fake_domain, TcpStream::connect(destination).await?)
            .await?;

        let (_, tls_session) = tls_conn.get_ref();
        let auth_peer = self
            .peer_certs
            .authenticate_peer(tls_session.peer_certificates())?;

        if auth_peer != peer {
            return Err(anyhow::anyhow!("Connected to unexpected peer"));
        }

        let framed =
            BidiFramed::<_, WriteHalf<TlsStream<TcpStream>>, ReadHalf<TlsStream<TcpStream>>>::new(
                tls_conn,
            )
            .to_any();

        Ok((peer, framed))
    }

    async fn listen(&self, bind_addr: String) -> Result<ConnectionListener<M>, anyhow::Error> {
        let verifier = AllowAnyAuthenticatedClient::new(self.cert_store.clone());
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(verifier)
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

/// Fake network stack used in tests
#[allow(unused_imports)]
pub mod mock {
    use crate::net::connect::{ConnectResult, Connector};
    use crate::net::framed::{BidiFramed, FramedTransport};
    use anyhow::Error;
    use fedimint_api::PeerId;
    use futures::{FutureExt, SinkExt, Stream, StreamExt};
    use std::collections::HashMap;
    use std::fmt::Debug;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf,
    };
    use tokio::sync::mpsc::Sender;
    use tokio::sync::Mutex;

    pub struct MockNetwork {
        clients: Arc<Mutex<HashMap<String, Sender<DuplexStream>>>>,
    }

    pub struct MockConnector {
        id: PeerId,
        clients: Arc<Mutex<HashMap<String, Sender<DuplexStream>>>>,
    }

    impl MockNetwork {
        #[allow(clippy::new_without_default)]
        pub fn new() -> MockNetwork {
            MockNetwork {
                clients: Arc::new(Default::default()),
            }
        }

        pub fn connector(&self, id: PeerId) -> MockConnector {
            MockConnector {
                id,
                clients: self.clients.clone(),
            }
        }
    }

    #[async_trait::async_trait]
    impl<M> Connector<M> for MockConnector
    where
        M: Debug + serde::Serialize + serde::de::DeserializeOwned + Send + Unpin + 'static,
    {
        async fn connect_framed(&self, destination: String, _peer: PeerId) -> ConnectResult<M> {
            let mut clients_lock = self.clients.lock().await;
            if let Some(client) = clients_lock.get_mut(&destination) {
                let (mut stream_our, stream_theirs) = tokio::io::duplex(43_689);
                client.send(stream_theirs).await.unwrap();
                let peer = do_handshake(self.id, &mut stream_our).await.unwrap();
                let framed = BidiFramed::<M, WriteHalf<DuplexStream>, ReadHalf<DuplexStream>>::new(
                    stream_our,
                )
                .to_any();
                Ok((peer, framed))
            } else {
                return Err(anyhow::anyhow!("can't connect"));
            }
        }

        async fn listen(
            &self,
            bind_addr: String,
        ) -> Result<Pin<Box<dyn Stream<Item = ConnectResult<M>> + Send + Unpin + 'static>>, Error>
        {
            let (send, receive) = tokio::sync::mpsc::channel(16);

            if self.clients.lock().await.insert(bind_addr, send).is_some() {
                return Err(anyhow::anyhow!("Address already bound"));
            }

            let our_id = self.id;
            let stream = futures::stream::unfold(receive, move |mut receive| {
                Box::pin(async move {
                    let mut connection = receive.recv().await.unwrap();
                    let peer = do_handshake(our_id, &mut connection).await.unwrap();
                    let framed =
                        BidiFramed::<M, WriteHalf<DuplexStream>, ReadHalf<DuplexStream>>::new(
                            connection,
                        )
                        .to_any();

                    Some((Ok((peer, framed)), receive))
                })
            });
            Ok(Box::pin(stream))
        }
    }

    async fn do_handshake<S>(our_id: PeerId, stream: &mut S) -> Result<PeerId, anyhow::Error>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        // Send our id
        let our_id = our_id.to_usize() as u16;
        stream.write_all(&our_id.to_le_bytes()[..]).await?;

        // Receive peer id
        let mut peer_id = [0u8; 2];
        stream.read_exact(&mut peer_id[..]).await?;
        Ok(PeerId::from(u16::from_le_bytes(peer_id)))
    }

    #[tokio::test]
    async fn test_mock_network() {
        let peer_a = PeerId::from(1);
        let peer_b = PeerId::from(2);

        let net = MockNetwork::new();
        let conn_a = net.connector(peer_a);
        let conn_b = net.connector(peer_b);

        let mut listener = Connector::<u64>::listen(&conn_a, "a".into()).await.unwrap();
        let conn_a_fut = tokio::spawn(async move { listener.next().await.unwrap().unwrap() });

        let (auth_peer_b, mut conn_b) =
            Connector::<u64>::connect_framed(&conn_b, "a".into(), peer_a)
                .await
                .unwrap();
        let (auth_peer_a, mut conn_a) = conn_a_fut.await.unwrap();

        assert_eq!(auth_peer_a, peer_b);
        assert_eq!(auth_peer_b, peer_a);

        conn_a.send(42).await.unwrap();
        conn_b.send(21).await.unwrap();

        assert_eq!(conn_a.next().await.unwrap().unwrap(), 21);
        assert_eq!(conn_b.next().await.unwrap().unwrap(), 42);
    }

    #[allow(dead_code)]
    async fn timeout<F, T>(f: F) -> Option<T>
    where
        F: Future<Output = T>,
    {
        tokio::time::timeout(Duration::from_secs(1), f).await.ok()
    }

    #[tokio::test]
    async fn test_large_messages() {
        let peer_a = PeerId::from(1);
        let peer_b = PeerId::from(2);

        let net = MockNetwork::new();
        let conn_a = net.connector(peer_a);
        let conn_b = net.connector(peer_b);

        let mut listener = Connector::<Vec<u8>>::listen(&conn_a, "a".into())
            .await
            .unwrap();
        let conn_a_fut = tokio::spawn(async move { listener.next().await.unwrap().unwrap() });

        let (auth_peer_b, mut conn_b) =
            Connector::<Vec<u8>>::connect_framed(&conn_b, "a".into(), peer_a)
                .await
                .unwrap();
        let (auth_peer_a, mut conn_a) = conn_a_fut.await.unwrap();

        assert_eq!(auth_peer_a, peer_b);
        assert_eq!(auth_peer_b, peer_a);

        let send_future = async move {
            conn_a.send(vec![42; 16000]).await.unwrap();
        }
        .boxed();
        let receive_future = async move {
            assert_eq!(
                timeout(conn_b.next()).await.unwrap().unwrap().unwrap(),
                vec![42; 16000]
            );
        }
        .boxed();

        tokio::join!(send_future, receive_future);
    }
}

#[cfg(test)]
mod tests {
    use crate::config::gen_cert_and_key;
    use crate::net::connect::{ConnectionListener, TlsConfig};
    use crate::net::framed::AnyFramedTransport;
    use crate::{Connector, TlsTcpConnector};
    use fedimint_api::PeerId;
    use futures::{SinkExt, StreamExt};

    fn gen_connector_config(count: usize) -> Vec<TlsConfig> {
        let peer_keys = (0..count)
            .map(|id| {
                let peer = PeerId::from(id as u16);
                let cert_key = gen_cert_and_key(&format!("peer-{}", peer.to_usize())).unwrap();
                cert_key
            })
            .collect::<Vec<_>>();

        peer_keys
            .iter()
            .map(|(cert, key)| TlsConfig {
                our_certificate: cert.clone(),
                our_private_key: key.clone(),
                peer_certs: peer_keys
                    .iter()
                    .enumerate()
                    .map(|(peer, (cert, _))| (PeerId::from(peer as u16), cert.clone()))
                    .collect(),
            })
            .collect()
    }

    #[tokio::test]
    async fn connect_success() {
        // FIXME: don't actually bind here, probably requires yet another Box<dyn Trait> layer :(
        let bind_addr = "127.0.0.1:7000".to_owned();
        let connectors = gen_connector_config(5)
            .into_iter()
            .map(TlsTcpConnector::new)
            .collect::<Vec<_>>();

        let mut server: ConnectionListener<u64> =
            connectors[0].listen(bind_addr.clone()).await.unwrap();

        let server_task = tokio::spawn(async move {
            let (peer, mut conn) = server.next().await.unwrap().unwrap();
            assert_eq!(peer.to_usize(), 2);
            let received = conn.next().await.unwrap().unwrap();
            assert_eq!(received, 42);
            conn.send(21).await.unwrap();
            assert!(conn.next().await.unwrap().is_err());
        });

        let (peer_of_a, mut client_a): (_, AnyFramedTransport<u64>) = connectors[2]
            .connect_framed(bind_addr.clone(), PeerId::from(0))
            .await
            .unwrap();
        assert_eq!(peer_of_a.to_usize(), 0);
        client_a.send(42).await.unwrap();
        let received = client_a.next().await.unwrap().unwrap();
        assert_eq!(received, 21);
        drop(client_a);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn connect_reject() {
        let bind_addr = "127.0.0.1:7001".to_owned();
        let cfg = gen_connector_config(5);

        let honest = TlsTcpConnector::new(cfg[0].clone());

        let mut malicious_wrong_key_cfg = cfg[1].clone();
        malicious_wrong_key_cfg.our_private_key = cfg[2].our_private_key.clone();
        let malicious_wrong_key = TlsTcpConnector::new(malicious_wrong_key_cfg);

        // Honest server, malicious client with wrong private key
        {
            let mut server: ConnectionListener<u64> =
                honest.listen(bind_addr.clone()).await.unwrap();

            let server_task = tokio::spawn(async move {
                let conn_res = server.next().await.unwrap();
                assert_eq!(
                    conn_res.err().unwrap().to_string().as_str(),
                    "invalid peer certificate signature"
                );
            });

            let err_anytime = async {
                let (_peer, mut conn): (_, AnyFramedTransport<u64>) = malicious_wrong_key
                    .connect_framed(bind_addr.clone(), PeerId::from(0))
                    .await?;

                conn.send(42).await?;
                conn.flush().await?;
                conn.next().await.unwrap()?;

                Result::<_, anyhow::Error>::Ok(())
            };

            let conn_res = err_anytime.await;
            assert_eq!(
                conn_res.err().unwrap().to_string().as_str(),
                "received fatal alert: AccessDenied"
            );

            server_task.await.unwrap();
        }

        // Malicious server with wrong key, honest client
        {
            let mut server: ConnectionListener<u64> =
                malicious_wrong_key.listen(bind_addr.clone()).await.unwrap();

            let server_task = tokio::spawn(async move {
                let conn_res = server.next().await.unwrap();
                assert_eq!(
                    conn_res.err().unwrap().to_string().as_str(),
                    "received fatal alert: BadCertificate"
                );
            });

            let err_anytime = async {
                let (_peer, mut conn): (_, AnyFramedTransport<u64>) = honest
                    .connect_framed(bind_addr.clone(), PeerId::from(1))
                    .await?;

                conn.send(42).await?;
                conn.flush().await?;
                conn.next().await.unwrap()?;

                Result::<_, anyhow::Error>::Ok(())
            };

            let conn_res = err_anytime.await;
            assert_eq!(
                conn_res.err().unwrap().to_string().as_str(),
                "invalid peer certificate signature"
            );

            server_task.await.unwrap();
        }

        // Server with wrong certificate, honest client
        {
            let mut server: ConnectionListener<u64> = TlsTcpConnector::new(cfg[2].clone())
                .listen(bind_addr.clone())
                .await
                .unwrap();

            let server_task = tokio::spawn(async move {
                let conn_res = server.next().await.unwrap();
                assert_eq!(
                    conn_res.err().unwrap().to_string().as_str(),
                    "received fatal alert: BadCertificate"
                );
            });

            let err_anytime = async {
                let (_peer, mut conn): (_, AnyFramedTransport<u64>) = honest
                    .connect_framed(bind_addr.clone(), PeerId::from(0))
                    .await?;

                conn.send(42).await?;
                conn.flush().await?;
                conn.next().await.unwrap()?;

                Result::<_, anyhow::Error>::Ok(())
            };

            let conn_res = err_anytime.await;
            assert_eq!(
                conn_res.err().unwrap().to_string().as_str(),
                "invalid peer certificate contents: invalid peer certificate: CertNotValidForName"
            );

            server_task.await.unwrap();
        }
    }
}
