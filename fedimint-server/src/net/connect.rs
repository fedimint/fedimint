//! Provides an abstract network connection interface and multiple
//! implementations

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::format_err;
use async_trait::async_trait;
use fedimint_core::util::SafeUrl;
use fedimint_core::PeerId;
use futures::Stream;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::server::AllowAnyAuthenticatedClient;
use tokio_rustls::rustls::RootCertStore;
use tokio_rustls::{rustls, TlsAcceptor, TlsConnector, TlsStream};

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
        for (_, cert) in cfg.peer_certs.iter() {
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

        let framed =
            BidiFramed::<_, WriteHalf<TlsStream<TcpStream>>, ReadHalf<TlsStream<TcpStream>>>::new(
                tls_conn,
            )
            .into_dyn();
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
            .with_single_cert(
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
                TcpStream::connect(parse_host_port(destination)?).await?,
            )
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
            .into_dyn();

        Ok((peer, framed))
    }

    async fn listen(&self, bind_addr: SocketAddr) -> Result<ConnectionListener<M>, anyhow::Error> {
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

/// Sanitizes name as valid domain name
pub fn dns_sanitize(name: &str) -> String {
    let sanitized = name.replace(|c: char| !c.is_ascii_alphanumeric(), "_");
    format!("peer{sanitized}")
}

/// Parses the host and port from a url
pub fn parse_host_port(url: SafeUrl) -> anyhow::Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| format_err!("Missing host in {url}"))?;
    let port = url
        .port()
        .ok_or_else(|| format_err!("Missing port in {url}"))?;

    Ok(format!("{host}:{port}"))
}

/// Fake network stack used in tests
#[allow(unused_imports)]
pub mod mock {
    use std::collections::HashMap;
    use std::fmt::Debug;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{anyhow, Error};
    use fedimint_core::task::{sleep, spawn};
    use fedimint_core::util::SafeUrl;
    use fedimint_core::{task, PeerId};
    use futures::{pin_mut, FutureExt, SinkExt, Stream, StreamExt};
    use rand::Rng;
    use tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf,
    };
    use tokio::sync::mpsc::Sender;
    use tokio::sync::Mutex;
    use tokio_util::sync::CancellationToken;
    use tracing::{error, instrument};

    use crate::net::connect::{parse_host_port, ConnectResult, Connector};
    use crate::net::framed::{BidiFramed, FramedTransport};

    struct UnreliableDuplexStream {
        inner: DuplexStream,
        broken: CancellationToken,
        read_generator: Option<UnreliabilityGenerator>,
        write_generator: Option<UnreliabilityGenerator>,
        flush_generator: Option<UnreliabilityGenerator>,
        shutdown_generator: Option<UnreliabilityGenerator>,
    }

    impl UnreliableDuplexStream {
        fn new(inner: DuplexStream, reliability: StreamReliability) -> UnreliableDuplexStream {
            match reliability {
                StreamReliability::FullyReliable => Self {
                    inner,
                    broken: CancellationToken::new(),
                    read_generator: None,
                    write_generator: None,
                    flush_generator: None,
                    shutdown_generator: None,
                },
                StreamReliability::RandomlyUnreliable {
                    read_failure_rate,
                    write_failure_rate,
                    flush_failure_rate,
                    shutdown_failure_rate,
                    read_latency,
                    write_latency,
                    flush_latency,
                    shutdown_latency,
                } => Self {
                    inner,
                    broken: CancellationToken::new(),
                    read_generator: Some(UnreliabilityGenerator::new(
                        read_latency,
                        read_failure_rate,
                    )),
                    write_generator: Some(UnreliabilityGenerator::new(
                        write_latency,
                        write_failure_rate,
                    )),
                    flush_generator: Some(UnreliabilityGenerator::new(
                        flush_latency,
                        flush_failure_rate,
                    )),
                    shutdown_generator: Some(UnreliabilityGenerator::new(
                        shutdown_latency,
                        shutdown_failure_rate,
                    )),
                },
            }
        }

        fn poll_broken(&self, cx: &mut std::task::Context<'_>) -> bool {
            let await_cancellation = self.broken.cancelled();
            pin_mut!(await_cancellation);
            await_cancellation.poll(cx).is_ready()
        }
    }

    impl Debug for UnreliableDuplexStream {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("UnreliableDuplexStream").finish()
        }
    }

    struct UnreliabilityGenerator {
        latency: LatencyInterval,
        failure_rate: FailureRate,
        sleep_future: Option<Pin<Box<tokio::time::Sleep>>>,
        successes: u64,
    }

    impl UnreliabilityGenerator {
        fn new(latency: LatencyInterval, failure_rate: FailureRate) -> UnreliabilityGenerator {
            Self {
                latency,
                failure_rate,
                sleep_future: None,
                successes: 0,
            }
        }

        pub fn generate(
            &mut self,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let sleep = self.sleep_future.get_or_insert_with(|| {
                Box::pin(
                    // nosemgrep: ban-tokio-sleep
                    tokio::time::sleep(self.latency.random()),
                )
            });
            match sleep.poll_unpin(cx) {
                std::task::Poll::Ready(()) => {
                    self.sleep_future = None;
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
            if self.failure_rate.random_fail() {
                tracing::debug!(
                    "Returning random error on unreliable stream after {} successes",
                    self.successes
                );
                std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Randomly failed",
                )))
            } else {
                self.successes += 1;
                std::task::Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncRead for UnreliableDuplexStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if self.poll_broken(cx) {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Stream is broken",
                )));
            }

            match self.read_generator.as_mut().map(|g| g.generate(cx)) {
                Some(std::task::Poll::Ready(Err(e))) => {
                    self.broken.cancel();
                    std::task::Poll::Ready(Err(e))
                }
                Some(std::task::Poll::Pending) => std::task::Poll::Pending,
                Some(std::task::Poll::Ready(Ok(()))) | None => {
                    Pin::new(&mut self.inner).poll_read(cx, buf)
                }
            }
        }
    }

    impl AsyncWrite for UnreliableDuplexStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            if self.poll_broken(cx) {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Stream is broken",
                )));
            }

            match self.write_generator.as_mut().map(|g| g.generate(cx)) {
                Some(std::task::Poll::Ready(Err(e))) => {
                    self.broken.cancel();
                    std::task::Poll::Ready(Err(e))
                }
                Some(std::task::Poll::Pending) => std::task::Poll::Pending,
                Some(std::task::Poll::Ready(Ok(()))) | None => {
                    Pin::new(&mut self.inner).poll_write(cx, buf)
                }
            }
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            if self.poll_broken(cx) {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Stream is broken",
                )));
            }

            match self.flush_generator.as_mut().map(|g| g.generate(cx)) {
                Some(std::task::Poll::Ready(Err(e))) => {
                    self.broken.cancel();
                    std::task::Poll::Ready(Err(e))
                }
                Some(std::task::Poll::Pending) => std::task::Poll::Pending,
                Some(std::task::Poll::Ready(Ok(()))) | None => {
                    Pin::new(&mut self.inner).poll_flush(cx)
                }
            }
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), std::io::Error>> {
            if self.poll_broken(cx) {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Stream is broken",
                )));
            }

            match self.shutdown_generator.as_mut().map(|g| g.generate(cx)) {
                Some(std::task::Poll::Ready(Err(e))) => {
                    self.broken.cancel();
                    std::task::Poll::Ready(Err(e))
                }
                Some(std::task::Poll::Pending) => std::task::Poll::Pending,
                Some(std::task::Poll::Ready(Ok(()))) | None => {
                    Pin::new(&mut self.inner).poll_shutdown(cx)
                }
            }
        }
    }

    pub struct MockNetwork {
        clients: Arc<Mutex<HashMap<String, Sender<UnreliableDuplexStream>>>>,
    }

    pub struct MockConnector {
        id: PeerId,
        clients: Arc<Mutex<HashMap<String, Sender<UnreliableDuplexStream>>>>,
        reliability: StreamReliability,
    }

    impl MockNetwork {
        #[allow(clippy::new_without_default)]
        pub fn new() -> MockNetwork {
            MockNetwork {
                clients: Arc::new(Default::default()),
            }
        }

        pub fn connector(&self, id: PeerId, reliability: StreamReliability) -> MockConnector {
            MockConnector {
                id,
                clients: self.clients.clone(),
                reliability,
            }
        }
    }

    #[derive(Debug, Copy, Clone, PartialEq, Eq)]
    pub struct LatencyInterval {
        min_millis: u64,
        max_millis: u64,
    }

    impl LatencyInterval {
        const ZERO: LatencyInterval = LatencyInterval {
            min_millis: 0,
            max_millis: 0,
        };

        pub fn new(min: Duration, max: Duration) -> LatencyInterval {
            assert!(min <= max);
            LatencyInterval {
                min_millis: min
                    .as_millis()
                    .try_into()
                    .expect("min duration as millis to fit in a u64"),
                max_millis: max
                    .as_millis()
                    .try_into()
                    .expect("max duration as millis to fit in a u64"),
            }
        }

        pub fn random(&self) -> Duration {
            let mut rng = rand::thread_rng();
            Duration::from_millis(rng.gen_range(self.min_millis..=self.max_millis))
        }
    }

    #[derive(Debug, Copy, Clone)]
    pub struct FailureRate(f64);
    impl FailureRate {
        const MAX: FailureRate = FailureRate(1.0);
        pub fn new(failure_rate: f64) -> Self {
            assert!((0.0..=1.0).contains(&failure_rate));
            Self(failure_rate)
        }

        pub fn random_fail(&self) -> bool {
            let mut rng = rand::thread_rng();
            rng.gen_range(0.0..1.0) < self.0
        }
    }

    #[derive(Debug, Copy, Clone)]
    pub enum StreamReliability {
        FullyReliable,
        RandomlyUnreliable {
            read_failure_rate: FailureRate,
            write_failure_rate: FailureRate,
            flush_failure_rate: FailureRate,
            shutdown_failure_rate: FailureRate,
            read_latency: LatencyInterval,
            write_latency: LatencyInterval,
            flush_latency: LatencyInterval,
            shutdown_latency: LatencyInterval,
        },
    }

    impl StreamReliability {
        pub const MILDLY_UNRELIABLE: StreamReliability = {
            let failure_rate = FailureRate(0.1);
            let latency = LatencyInterval {
                min_millis: 1,
                max_millis: 10,
            };
            Self::RandomlyUnreliable {
                read_failure_rate: failure_rate,
                write_failure_rate: failure_rate,
                flush_failure_rate: failure_rate,
                shutdown_failure_rate: failure_rate,
                read_latency: latency,
                write_latency: latency,
                flush_latency: latency,
                shutdown_latency: latency,
            }
        };

        pub const INTEGRATION_TEST: StreamReliability = {
            // Based on empirical testing: creates errors without causing tests to take
            // additional time compared to StreamReliability::FullyReliable
            // If an order of magnitude higher, tests may take unreasonable amounts of time.
            // If an order of magnitude lower, a test may run without any error actually
            // happening
            let failure_rate_base = 1e-3;
            let latency = LatencyInterval {
                min_millis: 1,
                max_millis: 10,
            };
            Self::RandomlyUnreliable {
                // Try to make read_failure_rate = write_failure_rate + flush_failure_rate
                read_failure_rate: FailureRate(failure_rate_base * 2.0),
                write_failure_rate: FailureRate(failure_rate_base),
                flush_failure_rate: FailureRate(failure_rate_base),
                shutdown_failure_rate: FailureRate(failure_rate_base),
                read_latency: latency,
                write_latency: latency,
                flush_latency: latency,
                shutdown_latency: latency,
            }
        };

        pub const BROKEN: StreamReliability = {
            Self::RandomlyUnreliable {
                read_failure_rate: FailureRate::MAX,
                write_failure_rate: FailureRate::MAX,
                flush_failure_rate: FailureRate::MAX,
                shutdown_failure_rate: FailureRate::MAX,
                read_latency: LatencyInterval::ZERO,
                write_latency: LatencyInterval::ZERO,
                flush_latency: LatencyInterval::ZERO,
                shutdown_latency: LatencyInterval::ZERO,
            }
        };
    }

    #[async_trait::async_trait]
    impl<M> Connector<M> for MockConnector
    where
        M: Debug + serde::Serialize + serde::de::DeserializeOwned + Send + Unpin + 'static,
    {
        async fn connect_framed(&self, destination: SafeUrl, _peer: PeerId) -> ConnectResult<M> {
            let mut clients_lock = self.clients.try_lock().map_err(|e| {
                anyhow!("Mock network mutex busy or poisoned, the network stack will re-try anyway: {e:?}")
            })?;
            if let Some(client) = clients_lock.get_mut(&parse_host_port(destination)?) {
                let (stream_our, stream_theirs) = tokio::io::duplex(43_689);
                let mut stream_our = UnreliableDuplexStream::new(stream_our, self.reliability);
                let stream_theirs = UnreliableDuplexStream::new(stream_theirs, self.reliability);
                client.send(stream_theirs).await?;
                let peer = do_handshake(self.id, &mut stream_our).await?;
                let framed = BidiFramed::<
                    M,
                    WriteHalf<UnreliableDuplexStream>,
                    ReadHalf<UnreliableDuplexStream>,
                >::new(stream_our)
                .into_dyn();
                Ok((peer, framed))
            } else {
                return Err(anyhow::anyhow!("can't connect"));
            }
        }

        async fn listen(
            &self,
            bind_addr: SocketAddr,
        ) -> Result<Pin<Box<dyn Stream<Item = ConnectResult<M>> + Send + Unpin + 'static>>, Error>
        {
            let (send, receive) = tokio::sync::mpsc::channel(16);

            if self
                .clients
                .lock()
                .await
                .insert(bind_addr.to_string(), send)
                .is_some()
            {
                return Err(anyhow::anyhow!("Address already bound"));
            }

            let our_id = self.id;
            let stream = futures::stream::unfold(receive, move |mut receive| {
                Box::pin(async move {
                    let mut connection = receive.recv().await.unwrap();
                    let peer = match do_handshake(our_id, &mut connection).await {
                        Ok(peer) => peer,
                        Err(e) => {
                            tracing::debug!("Error during handshake: {e:?}");
                            return Some((Err(e), receive));
                        }
                    };
                    let framed =
                        BidiFramed::<M, WriteHalf<DuplexStream>, ReadHalf<DuplexStream>>::new(
                            connection,
                        )
                        .into_dyn();

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
        stream.write_all(&our_id.to_be_bytes()[..]).await?;

        // Receive peer id
        let mut peer_id = [0u8; 2];
        stream.read_exact(&mut peer_id[..]).await?;
        Ok(PeerId::from(u16::from_be_bytes(peer_id)))
    }

    #[tokio::test]
    #[instrument(level = "info")]
    async fn test_mock_network() {
        let bind_addr: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let url: SafeUrl = "ws://127.0.0.1:7000".parse().unwrap();
        let peer_a = PeerId::from(1);
        let peer_b = PeerId::from(2);

        let net = MockNetwork::new();
        let conn_a = net.connector(peer_a, StreamReliability::FullyReliable);
        let conn_b = net.connector(peer_b, StreamReliability::FullyReliable);

        let mut listener = Connector::<u64>::listen(&conn_a, bind_addr).await.unwrap();
        let conn_a_fut = spawn("listener next await", async move {
            listener.next().await.unwrap().unwrap()
        })
        .expect("some handle on non-wasm");

        let (auth_peer_b, mut conn_b) = Connector::<u64>::connect_framed(&conn_b, url, peer_a)
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

    #[tokio::test]
    #[instrument(level = "info")]
    async fn test_unreliable_components() {
        assert!(!FailureRate::new(0f64).random_fail());
        assert!(FailureRate::new(1f64).random_fail());

        let good_interval = (0..=3).contains(
            &LatencyInterval::new(Duration::from_millis(0), Duration::from_millis(3))
                .random()
                .as_millis(),
        );
        assert!(good_interval);

        let (a, b) = tokio::io::duplex(43_689);
        let mut a_stream = UnreliableDuplexStream::new(a, StreamReliability::FullyReliable);
        let mut b_stream = UnreliableDuplexStream::new(b, StreamReliability::FullyReliable);
        assert!(a_stream.write(&[1, 2, 3]).await.is_ok());
        assert!(a_stream.flush().await.is_ok());
        assert_eq!(b_stream.read_u8().await.unwrap(), 1);
        assert_eq!(b_stream.read_u8().await.unwrap(), 2);
        assert_eq!(b_stream.read_u8().await.unwrap(), 3);

        let (a, b) = tokio::io::duplex(43_689);
        let mut a_stream = UnreliableDuplexStream::new(a, StreamReliability::FullyReliable);
        let mut b_stream = UnreliableDuplexStream::new(b, StreamReliability::BROKEN);
        assert!(a_stream.write(&[1, 2, 3]).await.is_ok());
        assert!(a_stream.flush().await.is_ok());
        assert!(b_stream.read_u8().await.is_err());

        let (a, b) = tokio::io::duplex(43_689);
        let mut a_stream = UnreliableDuplexStream::new(a, StreamReliability::BROKEN);
        let mut _b_stream = UnreliableDuplexStream::new(b, StreamReliability::FullyReliable);
        assert!(a_stream.write(&[1, 2, 3]).await.is_err());
        // a read on _b_stream would block...
    }

    #[allow(dead_code)]
    async fn timeout<F, T>(f: F) -> Option<T>
    where
        F: Future<Output = T>,
    {
        tokio::time::timeout(Duration::from_secs(1), f).await.ok()
    }

    #[tokio::test]
    #[instrument(level = "info")]
    async fn test_large_messages() {
        let bind_addr: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let url: SafeUrl = "ws://127.0.0.1:7000".parse().unwrap();
        let peer_a = PeerId::from(1);
        let peer_b = PeerId::from(2);

        let net = MockNetwork::new();
        let conn_a = net.connector(peer_a, StreamReliability::FullyReliable);
        let conn_b = net.connector(peer_b, StreamReliability::FullyReliable);

        let mut listener = Connector::<Vec<u8>>::listen(&conn_a, bind_addr)
            .await
            .unwrap();
        let conn_a_fut = spawn("listener next await", async move {
            listener.next().await.unwrap().unwrap()
        })
        .expect("some handle on non-wasm");

        let (auth_peer_b, mut conn_b) = Connector::<Vec<u8>>::connect_framed(&conn_b, url, peer_a)
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
    use std::net::SocketAddr;

    use fedimint_core::task::spawn;
    use fedimint_core::util::SafeUrl;
    use fedimint_core::PeerId;
    use futures::{SinkExt, StreamExt};
    use tracing::instrument;

    use crate::config::gen_cert_and_key;
    use crate::net::connect::{ConnectionListener, Connector, TlsConfig};
    use crate::net::framed::AnyFramedTransport;
    use crate::TlsTcpConnector;

    fn gen_connector_config(count: usize) -> Vec<TlsConfig> {
        let peer_keys = (0..count)
            .map(|id| {
                let peer = PeerId::from(id as u16);
                gen_cert_and_key(&format!("peer-{}", peer.to_usize())).unwrap()
            })
            .collect::<Vec<_>>();

        peer_keys
            .iter()
            .map(|(_cert, key)| TlsConfig {
                our_private_key: key.clone(),
                peer_certs: peer_keys
                    .iter()
                    .enumerate()
                    .map(|(peer, (cert, _))| (PeerId::from(peer as u16), cert.clone()))
                    .collect(),
                peer_names: peer_keys
                    .iter()
                    .enumerate()
                    .map(|(peer, (_, _))| (PeerId::from(peer as u16), format!("peer-{peer}")))
                    .collect(),
            })
            .collect()
    }

    #[tokio::test]
    #[instrument(level = "info")]
    async fn connect_success() {
        // FIXME: don't actually bind here, probably requires yet another Box<dyn Trait>
        // layer :(
        let bind_addr: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let url: SafeUrl = "ws://127.0.0.1:7000".parse().unwrap();
        let connectors = gen_connector_config(5)
            .into_iter()
            .enumerate()
            .map(|(id, cfg)| TlsTcpConnector::new(cfg, PeerId::from(id as u16)))
            .collect::<Vec<_>>();

        let mut server: ConnectionListener<u64> = connectors[0].listen(bind_addr).await.unwrap();

        let server_task = spawn("server next await", async move {
            let (peer, mut conn) = server.next().await.unwrap().unwrap();
            assert_eq!(peer.to_usize(), 2);
            let received = conn.next().await.unwrap().unwrap();
            assert_eq!(received, 42);
            conn.send(21).await.unwrap();
            assert!(conn.next().await.unwrap().is_err());
        })
        .expect("some handle on non-wasm");

        let (peer_of_a, mut client_a): (_, AnyFramedTransport<u64>) = connectors[2]
            .connect_framed(url.clone(), PeerId::from(0))
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
    #[instrument(level = "info")]
    async fn connect_reject() {
        let bind_addr: SocketAddr = "127.0.0.1:7001".parse().unwrap();
        let url: SafeUrl = "wss://127.0.0.1:7001".parse().unwrap();
        let cfg = gen_connector_config(5);

        let honest = TlsTcpConnector::new(cfg[0].clone(), PeerId::from(0));

        let mut malicious_wrong_key_cfg = cfg[1].clone();
        malicious_wrong_key_cfg.our_private_key = cfg[2].our_private_key.clone();
        let malicious_wrong_key = TlsTcpConnector::new(malicious_wrong_key_cfg, PeerId::from(1));

        // Honest server, malicious client with wrong private key
        {
            let mut server: ConnectionListener<u64> = honest.listen(bind_addr).await.unwrap();

            let server_task = spawn("server next await", async move {
                let conn_res = server.next().await.unwrap();
                assert_eq!(
                    conn_res.err().unwrap().to_string().as_str(),
                    "invalid peer certificate signature"
                );
            })
            .expect("some handle on non-wasm");

            let err_anytime = async {
                let (_peer, mut conn): (_, AnyFramedTransport<u64>) = malicious_wrong_key
                    .connect_framed(url.clone(), PeerId::from(0))
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
                malicious_wrong_key.listen(bind_addr).await.unwrap();

            let server_task = spawn("server next await", async move {
                let conn_res = server.next().await.unwrap();
                assert_eq!(
                    conn_res.err().unwrap().to_string().as_str(),
                    "received fatal alert: BadCertificate"
                );
            })
            .expect("some handle on non-wasm");

            let err_anytime = async {
                let (_peer, mut conn): (_, AnyFramedTransport<u64>) =
                    honest.connect_framed(url.clone(), PeerId::from(1)).await?;

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
            let mut server: ConnectionListener<u64> =
                TlsTcpConnector::new(cfg[2].clone(), PeerId::from(2))
                    .listen(bind_addr)
                    .await
                    .unwrap();

            let server_task = spawn("server next await", async move {
                let conn_res = server.next().await.unwrap();
                assert_eq!(
                    conn_res.err().unwrap().to_string().as_str(),
                    "received fatal alert: BadCertificate"
                );
            })
            .expect("some handle on non-wasm");

            let err_anytime = async {
                let (_peer, mut conn): (_, AnyFramedTransport<u64>) =
                    honest.connect_framed(url.clone(), PeerId::from(0)).await?;

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
