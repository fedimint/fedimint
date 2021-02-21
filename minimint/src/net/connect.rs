use crate::net::framed::Framed;
use crate::net::PeerConnections;
use async_trait::async_trait;
use config::ServerConfig;
use futures::future::select_all;
use futures::future::try_join_all;
use futures::StreamExt;
use futures::{FutureExt, SinkExt};
use hbbft::Target;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::spawn;
use tokio::time::sleep;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use tracing::{debug, error, info, trace};

// FIXME: make connections dynamically managed
pub struct Connections<T> {
    connections: HashMap<u16, Framed<Compat<TcpStream>, T>>,
}

impl<T: 'static> Connections<T>
where
    T: Serialize + DeserializeOwned + Unpin + Send,
{
    pub async fn connect_to_all(cfg: &ServerConfig) -> Self {
        info!("Starting mint {}", cfg.identity);
        let listener = spawn(Self::await_peers(
            cfg.get_hbbft_port(),
            cfg.get_incoming_count(),
        ));

        sleep(Duration::from_millis(5000)).await;

        debug!("Beginning to connect to peers");

        let out_conns = try_join_all(cfg.peers.iter().filter_map(|(id, peer)| {
            if cfg.identity < *id {
                info!("Connecting to mint {}", id);
                Some(Self::connect_to_peer(peer.hbbft_port, *id))
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
        let handshakes = out_conns.into_iter().chain(in_conns).map(
            async move |mut stream| -> Result<_, std::io::Error> {
                stream.write_u16(*identity).await?;
                let peer = stream.read_u16().await?;
                Ok((peer, stream))
            },
        );

        let peers = try_join_all(handshakes)
            .await
            .expect("Error during peer handshakes")
            .into_iter()
            .map(|(id, stream)| (id, Framed::new(stream.compat())))
            .collect::<HashMap<_, _>>();

        info!("Successfully connected to all peers");

        Connections { connections: peers }
    }

    async fn await_peers(port: u16, num_awaited: u16) -> Result<Vec<TcpStream>, std::io::Error> {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("Couldn't bind to port.");

        debug!("Listening for incoming connections on port {}", port);

        let peers = (0..num_awaited).map(|_| listener.accept());
        let connections = try_join_all(peers)
            .await?
            .into_iter()
            .map(|(socket, _)| socket)
            .collect::<Vec<_>>();

        debug!("Received all {} connections", connections.len());
        Ok(connections)
    }

    async fn connect_to_peer(port: u16, peer: u16) -> Result<TcpStream, std::io::Error> {
        debug!("Connecting to peer {}", peer);
        let res = TcpStream::connect(("127.0.0.1", port)).await;
        if res.is_err() {
            error!("Could not connect to peer {}", peer);
        }
        res
    }

    async fn receive_from_peer(id: u16, peer: &mut Framed<Compat<TcpStream>, T>) -> (u16, T) {
        let msg = peer
            .next()
            .await
            .expect("Stream closed unexpectedly")
            .expect("Error receiving peer message");

        trace!("Received msg from peer {}", id);

        (id, msg)
    }
}

#[async_trait]
impl<T> PeerConnections<T> for Connections<T>
where
    T: Serialize + DeserializeOwned + Unpin + Send + Sync + 'static,
{
    type Id = u16;

    async fn send(&mut self, target: Target<Self::Id>, msg: T) {
        trace!("Sending message to {:?}", target);
        match target {
            Target::All => {
                for peer in self.connections.values_mut() {
                    peer.send(&msg)
                        .await
                        .expect("Failed to send message to peer");
                }
            }
            Target::Node(peer_id) => {
                let peer = self.connections.get_mut(&peer_id).expect("Unknown peer");
                peer.send(&msg)
                    .await
                    .expect("Failed to send message to peer");
            }
        }
    }

    async fn receive(&mut self) -> (Self::Id, T) {
        // TODO: optimize, don't throw away remaining futures
        select_all(
            self.connections
                .iter_mut()
                .map(|(id, peer)| Self::receive_from_peer(id.clone(), peer).boxed()),
        )
        .map(|(msg, _, _)| msg)
        .await
    }
}
