use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use futures::future::select_all;
use futures::future::try_join_all;
use futures::StreamExt;
use futures::{FutureExt, SinkExt};
use hbbft::Target;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::spawn;
use tokio::time::sleep;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use tracing::{debug, info, instrument, trace, warn};

use minimint_api::PeerId;

use crate::config::ServerConfig;
use crate::net::framed::Framed;
use crate::net::PeerConnections;

// FIXME: make connections dynamically managed
pub struct Connections<T> {
    connections: HashMap<PeerId, Framed<Compat<TcpStream>, T>>,
}

impl<T: 'static> Connections<T>
where
    T: Serialize + DeserializeOwned + Unpin + Send,
{
    #[instrument(skip_all)]
    pub async fn connect_to_all(cfg: &ServerConfig) -> Self {
        info!("Starting mint {}", cfg.identity);
        let listener = spawn(Self::await_peers(
            cfg.get_hbbft_port(),
            cfg.get_incoming_count(),
        ));

        debug!("Beginning to connect to peers");

        let out_conns = try_join_all(cfg.peers.iter().filter_map(|(id, peer)| {
            if cfg.identity < *id {
                info!("Connecting to mint {}", id);
                Some(Self::connect_to_peer(peer.hbbft_port, *id, 10))
            } else {
                None
            }
        }))
        .await
        .expect("Failed to connect to peer");

        let in_conns = listener
            .await
            .unwrap()
            .expect("Failed to accept connection");

        let identity = &cfg.identity;
        let handshakes = out_conns
            .into_iter()
            .chain(in_conns)
            .map(move |mut stream| async move {
                stream.write_u16((*identity).into()).await?;
                let peer = stream.read_u16().await?.into();
                Result::<_, std::io::Error>::Ok((peer, stream))
            });

        let peers = try_join_all(handshakes)
            .await
            .expect("Error during peer handshakes")
            .into_iter()
            .map(|(id, stream)| (id, Framed::new(stream.compat())))
            .collect::<HashMap<_, _>>();

        info!("Successfully connected to all peers");

        Connections { connections: peers }
    }

    pub fn drop_peer(&mut self, peer: &PeerId) {
        self.connections.remove(peer);
        warn!("Peer {} dropped.", peer);
    }

    #[instrument]
    async fn await_peers(port: u16, num_awaited: u16) -> Result<Vec<TcpStream>, std::io::Error> {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("Couldn't bind to port.");

        debug!("Listening for incoming connections");

        let peers = (0..num_awaited).map(|_| listener.accept());
        let connections = try_join_all(peers)
            .await?
            .into_iter()
            .map(|(socket, _)| socket)
            .collect::<Vec<_>>();

        debug!("Received all {} connections", connections.len());
        Ok(connections)
    }

    async fn connect_to_peer(
        port: u16,
        peer: PeerId,
        retries: u32,
    ) -> Result<TcpStream, std::io::Error> {
        debug!("Connecting to peer {}", peer);
        let mut counter = 0;
        loop {
            let res = TcpStream::connect(("127.0.0.1", port)).await;
            if res.is_ok() || counter >= retries {
                return res;
            }
            counter += 1;
            sleep(Duration::from_millis(500)).await;
        }
    }

    async fn receive_from_peer(id: PeerId, peer: &mut Framed<Compat<TcpStream>, T>) -> Option<T> {
        let msg = peer.next().await?.ok()?;

        trace!(peer = %id, "Received msg");

        Some(msg)
    }
}

#[async_trait]
impl<T> PeerConnections<T> for Connections<T>
where
    T: Serialize + DeserializeOwned + Unpin + Send + Sync + 'static,
{
    type Id = PeerId;

    async fn send(&mut self, target: Target<Self::Id>, msg: T) {
        trace!(?target, "Sending message to");
        match target {
            Target::All => {
                for peer in self.connections.values_mut() {
                    if peer.send(&msg).await.is_err() {
                        warn!("Failed to send message to peer");
                    }
                }
            }
            Target::Node(peer_id) => {
                if let Some(peer) = self.connections.get_mut(&peer_id) {
                    if peer.send(&msg).await.is_err() {
                        warn!("Failed to send message to peer");
                    }
                }
            }
        }
    }

    async fn receive(&mut self) -> (Self::Id, T) {
        // TODO: optimize, don't throw away remaining futures
        loop {
            let (received, _, _) = select_all(self.connections.iter_mut().map(|(id, peer)| {
                let future = async move { (*id, Self::receive_from_peer(*id, peer).await) };
                future.boxed()
            }))
            .await;

            match received {
                (peer, Some(msg)) => return (peer, msg),
                (peer, None) => {
                    self.connections.remove(&peer);
                }
            }
        }
    }
}
