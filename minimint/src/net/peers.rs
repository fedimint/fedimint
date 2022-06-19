use crate::config::ServerConfig;
use crate::net::connect::{AnyConnector, ConnectResult, ConnectionListener};
use crate::net::framed::{AnyFramedTransport, FramedTransport};
use async_trait::async_trait;
use futures::future::select_all;
use futures::future::try_join_all;
use futures::{FutureExt, SinkExt, StreamExt, TryStreamExt};
use hbbft::Target;
use minimint_api::PeerId;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info, instrument, trace, warn};

type AnyPeerConnections<M> = Box<dyn PeerConnections<M> + Send + Unpin + 'static>;

#[async_trait]
pub trait PeerConnections<T>
where
    T: Serialize + DeserializeOwned + Unpin + Send,
{
    async fn send(&mut self, target: Target<PeerId>, msg: T);

    async fn receive(&mut self) -> (PeerId, T);

    async fn ban_peer(&mut self, peer: PeerId);

    fn to_any(self) -> AnyPeerConnections<T>
    where
        Self: Sized + Send + Unpin + 'static,
    {
        Box::new(self)
    }
}

// FIXME: make connections dynamically managed
pub struct TcpPeerConnections<T> {
    connections: HashMap<PeerId, AnyFramedTransport<T>>,
}

impl<T: 'static> TcpPeerConnections<T>
where
    T: std::fmt::Debug + Serialize + DeserializeOwned + Unpin + Send + Sync,
{
    #[instrument(skip_all)]
    pub async fn connect_to_all(cfg: &ServerConfig, connect: AnyConnector<T>) -> Self {
        info!("Starting mint {}", cfg.identity);
        let listener = connect
            .listen(format!("127.0.0.1:{}", cfg.get_hbbft_port()))
            .await
            .unwrap();
        let listener_task = tokio::spawn(Self::await_peers(listener, cfg.get_incoming_count()));

        debug!("Beginning to connect to peers");

        let out_conns = try_join_all(cfg.peers.iter().filter_map(|(id, peer)| {
            if cfg.identity < *id {
                info!("Connecting to mint {} at 127.0.0.1:{}", id, peer.hbbft_port);
                Some(Self::connect_to_peer(&connect, peer.hbbft_port, *id, 10))
            } else {
                None
            }
        }))
        .await
        .expect("Failed to connect to peer");

        let in_conns = listener_task
            .await
            .unwrap()
            .expect("Failed to accept connection");

        let peers = out_conns
            .into_iter()
            .chain(in_conns)
            .collect::<HashMap<_, _>>();

        info!("Successfully connected to all peers");

        TcpPeerConnections { connections: peers }
    }

    #[instrument(skip_all)]
    async fn await_peers(
        listener: ConnectionListener<T>,
        num_awaited: u16,
    ) -> Result<Vec<(PeerId, AnyFramedTransport<T>)>, anyhow::Error> {
        debug!("Listening for incoming connections");

        let connections = listener
            .take(num_awaited as usize)
            .try_collect::<Vec<_>>()
            .await?;

        debug!("Received all {} connections", connections.len());
        Ok(connections)
    }

    async fn connect_to_peer(
        connect: &AnyConnector<T>,
        port: u16,
        peer: PeerId,
        retries: u32,
    ) -> ConnectResult<T> {
        debug!("Connecting to peer {}", peer);
        let mut counter = 0;
        loop {
            let res = connect.connect_framed(format!("127.0.0.1:{}", port)).await;
            if res.is_ok() || counter >= retries {
                return res;
            }
            counter += 1;
            sleep(Duration::from_millis(500)).await;
        }
    }

    async fn receive_from_peer(
        id: PeerId,
        peer: &mut (dyn FramedTransport<T> + Send + Unpin),
    ) -> Option<T> {
        let msg = peer.next().await?.ok()?;

        trace!(peer = %id, "Received msg");

        Some(msg)
    }
}

#[async_trait]
impl<T> PeerConnections<T> for TcpPeerConnections<T>
where
    T: std::fmt::Debug + Serialize + DeserializeOwned + Clone + Unpin + Send + Sync + 'static,
{
    async fn send(&mut self, target: Target<PeerId>, msg: T) {
        trace!(?target, "Sending message to");
        match target {
            Target::All => {
                for peer in self.connections.values_mut() {
                    if let Err(e) = peer.send(msg.clone()).await {
                        warn!("Failed to send message to peer: {}", e);
                    }
                }
            }
            Target::Node(peer_id) => {
                if let Some(peer) = self.connections.get_mut(&peer_id) {
                    if let Err(e) = peer.send(msg.clone()).await {
                        warn!("Failed to send message to peer: {}", e);
                    }
                }
            }
        }
    }

    async fn receive(&mut self) -> (PeerId, T) {
        // TODO: optimize, don't throw away remaining futures
        loop {
            let (received, _, _) = select_all(self.connections.iter_mut().map(|(id, peer)| {
                let future = async move { (*id, Self::receive_from_peer(*id, &mut **peer).await) };
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

    async fn ban_peer(&mut self, peer: PeerId) {
        self.connections.remove(&peer);
        warn!("Peer {} dropped.", peer);
    }
}
