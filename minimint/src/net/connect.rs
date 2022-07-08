//! Provides an abstract network connection interface and multiple implementations

use crate::net::framed::{AnyFramedTransport, BidiFramed, FramedTransport};
use async_trait::async_trait;
use futures::Stream;
use minimint_api::PeerId;
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
    async fn connect_framed(&self, destination: String) -> ConnectResult<M>;

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

/// TCP connector without encryption or authentication, **not suitable for production deployments**
pub struct InsecureTcpConnector {
    our_id: PeerId,
}

impl InsecureTcpConnector {
    pub fn new(us: PeerId) -> Self {
        InsecureTcpConnector { our_id: us }
    }
}

#[async_trait]
impl<M> Connector<M> for InsecureTcpConnector
where
    M: Debug + serde::Serialize + serde::de::DeserializeOwned + Send + Unpin + 'static,
{
    async fn connect_framed(&self, destination: String) -> ConnectResult<M> {
        let mut connection = TcpStream::connect(destination).await?;
        let peer = do_handshake(self.our_id, &mut connection).await?;
        Ok((peer, Box::new(BidiFramed::new_from_tcp(connection))))
    }

    async fn listen(
        &self,
        bind_addr: String,
    ) -> Result<Pin<Box<dyn Stream<Item = ConnectResult<M>> + Send + Unpin + 'static>>, anyhow::Error>
    {
        let listener = TcpListener::bind(bind_addr).await?;
        let our_id = self.our_id;

        let stream = futures::stream::unfold(listener, move |listener| {
            Box::pin(async move {
                let res = listener.accept().await;

                let res = match res {
                    Ok((mut connection, _)) => do_handshake(our_id, &mut connection)
                        .await
                        .map(|peer| (peer, BidiFramed::new_from_tcp(connection).to_any())),
                    Err(e) => Err(anyhow::Error::new(e)),
                };

                Some((res, listener))
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

/// Fake network stack used in tests
#[allow(unused_imports)]
pub mod mock {
    use crate::net::connect::{do_handshake, ConnectResult, Connector};
    use crate::net::framed::{BidiFramed, FramedTransport};
    use anyhow::Error;
    use futures::{FutureExt, SinkExt, Stream, StreamExt};
    use minimint_api::PeerId;
    use std::collections::HashMap;
    use std::fmt::Debug;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{DuplexStream, ReadHalf, WriteHalf};
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
        async fn connect_framed(&self, destination: String) -> ConnectResult<M> {
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

    #[tokio::test]
    async fn test_mock_network() {
        let peer_a = PeerId::from(1);
        let peer_b = PeerId::from(2);

        let net = MockNetwork::new();
        let conn_a = net.connector(peer_a);
        let conn_b = net.connector(peer_b);

        let mut listener = Connector::<u64>::listen(&conn_a, "a".into()).await.unwrap();
        let conn_a_fut = tokio::spawn(async move { listener.next().await.unwrap().unwrap() });

        let (auth_peer_b, mut conn_b) = Connector::<u64>::connect_framed(&conn_b, "a".into())
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

        let (auth_peer_b, mut conn_b) = Connector::<Vec<u8>>::connect_framed(&conn_b, "a".into())
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
