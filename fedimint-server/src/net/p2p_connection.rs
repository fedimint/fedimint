#[cfg(test)]
mod tests;

use std::io::Cursor;
use std::pin::Pin;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_server_core::dashboard_ui::ConnectionType;
use futures::{SinkExt, Stream, StreamExt};
use iroh_next::endpoint::{Connection as IrohV1Connection, RecvStream as IrohV1RecvStream};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::TcpStream;
use tokio_rustls::TlsStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Maximum size of a p2p message in bytes. The largest message we expect to
/// receive is a signed session outcome.
const MAX_P2P_MESSAGE_SIZE: usize = 10_000_000;

pub type DynP2PConnection<M> = Box<dyn IP2PConnection<M>>;

pub type DynIP2PFrame<M> = Box<dyn IP2PFrame<M>>;

/// Type-erased stream notifying the P2P state machine that connection metadata
/// may have changed.
pub type DynConnectionStatusUpdates = Pin<Box<dyn Stream<Item = ()> + Send + 'static>>;

#[async_trait]
pub trait IP2PFrame<M>: Send + 'static {
    /// Read the entire frame from the connection and deserialize it into a
    /// message. This is *not* required to be cancel-safe.
    async fn read_to_end(&mut self) -> anyhow::Result<M>;

    fn into_dyn(self) -> DynIP2PFrame<M>
    where
        Self: Sized,
    {
        Box::new(self)
    }
}

#[async_trait]
pub trait IP2PConnection<M>: Send + 'static {
    /// Send a message over the connection. This is *not* required to be
    /// cancel-safe.
    async fn send(&mut self, message: M) -> anyhow::Result<()>;

    /// Receive a p2p frame from the connection. This is *required* to be
    /// cancel-safe.
    async fn receive(&mut self) -> anyhow::Result<DynIP2PFrame<M>>;

    /// Get the round-trip time of the connection.
    fn rtt(&self) -> Option<Duration>;

    /// Get the transport type currently backing this live connection.
    fn connection_type(&self) -> Option<ConnectionType> {
        None
    }

    /// Subscribe to notifications that the live connection metadata may have
    /// changed.
    ///
    /// Implementations should treat these as wake-ups only. The state machine
    /// reads a fresh [`Self::connection_type`] and [`Self::rtt`] snapshot after
    /// each notification. `None` means notifications are unsupported, while the
    /// end of a returned stream means there will be no more notifications.
    fn connection_status_updates(&self) -> Option<DynConnectionStatusUpdates> {
        None
    }

    fn into_dyn(self) -> DynP2PConnection<M>
    where
        Self: Sized,
    {
        Box::new(self)
    }
}

/// Implementations of the IP2PFrame and IP2PConnection traits for TLS

#[async_trait]
impl<M> IP2PFrame<M> for BytesMut
where
    M: Decodable + DeserializeOwned + Send + 'static,
{
    async fn read_to_end(&mut self) -> anyhow::Result<M> {
        if let Ok(message) = M::consensus_decode_whole(self, &ModuleDecoderRegistry::default()) {
            return Ok(message);
        }

        Ok(bincode::deserialize_from(Cursor::new(&**self))?)
    }
}

#[async_trait]
impl<M> IP2PConnection<M> for Framed<TlsStream<TcpStream>, LengthDelimitedCodec>
where
    M: Encodable + Decodable + Serialize + DeserializeOwned + Send + 'static,
{
    async fn send(&mut self, message: M) -> anyhow::Result<()> {
        let mut bytes = Vec::new();

        bincode::serialize_into(&mut bytes, &message)?;

        SinkExt::send(self, Bytes::from_owner(bytes)).await?;

        Ok(())
    }

    async fn receive(&mut self) -> anyhow::Result<DynIP2PFrame<M>> {
        let message = self
            .next()
            .await
            .context("Framed stream is closed")??
            .into_dyn();

        Ok(message)
    }

    fn rtt(&self) -> Option<Duration> {
        None
    }

    fn connection_type(&self) -> Option<ConnectionType> {
        Some(ConnectionType::Direct)
    }
}

/// Compatibility implementations for the public Iroh 0.35 connection types.

#[async_trait]
impl<M> IP2PFrame<M> for iroh::endpoint::RecvStream
where
    M: Decodable + DeserializeOwned + Send + 'static,
{
    async fn read_to_end(&mut self) -> anyhow::Result<M> {
        let bytes = self.read_to_end(MAX_P2P_MESSAGE_SIZE).await?;

        if let Ok(message) = M::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default()) {
            return Ok(message);
        }

        Ok(bincode::deserialize_from(Cursor::new(&bytes))?)
    }
}

#[async_trait]
impl<M> IP2PConnection<M> for iroh::endpoint::Connection
where
    M: Encodable + Decodable + Serialize + DeserializeOwned + Send + 'static,
{
    async fn send(&mut self, message: M) -> anyhow::Result<()> {
        let mut bytes = Vec::new();

        bincode::serialize_into(&mut bytes, &message)?;

        let mut sink = self.open_uni().await?;

        sink.write_all(&bytes).await?;
        sink.finish()?;

        Ok(())
    }

    async fn receive(&mut self) -> anyhow::Result<DynIP2PFrame<M>> {
        Ok(self.accept_uni().await?.into_dyn())
    }

    fn rtt(&self) -> Option<Duration> {
        Some(iroh::endpoint::Connection::rtt(self))
    }
}

/// Implementations of the P2P traits for Iroh 1.0.

#[async_trait]
impl<M> IP2PFrame<M> for IrohV1RecvStream
where
    M: Decodable + DeserializeOwned + Send + 'static,
{
    async fn read_to_end(&mut self) -> anyhow::Result<M> {
        let bytes = self.read_to_end(MAX_P2P_MESSAGE_SIZE).await?;

        if let Ok(message) = M::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default()) {
            return Ok(message);
        }

        Ok(bincode::deserialize_from(Cursor::new(&bytes))?)
    }
}

#[async_trait]
impl<M> IP2PConnection<M> for IrohV1Connection
where
    M: Encodable + Decodable + Serialize + DeserializeOwned + Send + 'static,
{
    async fn send(&mut self, message: M) -> anyhow::Result<()> {
        let mut bytes = Vec::new();

        bincode::serialize_into(&mut bytes, &message)?;

        let mut sink = self.open_uni().await?;

        sink.write_all(&bytes).await?;

        sink.finish()?;

        Ok(())
    }

    async fn receive(&mut self) -> anyhow::Result<DynIP2PFrame<M>> {
        Ok(self.accept_uni().await?.into_dyn())
    }

    fn rtt(&self) -> Option<Duration> {
        self.paths()
            .iter()
            .find(iroh_next::endpoint::Path::is_selected)
            .and_then(|path| IrohV1Connection::rtt(self, path.id()))
    }

    fn connection_type(&self) -> Option<ConnectionType> {
        connection_type_from_paths(self.paths().iter().map(|path| IrohPath {
            selected: path.is_selected(),
            kind: if path.is_ip() {
                IrohPathKind::Direct
            } else if path.is_relay() {
                IrohPathKind::Relay
            } else {
                IrohPathKind::Unknown
            },
        }))
    }

    fn connection_status_updates(&self) -> Option<DynConnectionStatusUpdates> {
        Some(Box::pin(self.path_events().map(|_| ())))
    }
}

#[derive(Clone, Copy)]
enum IrohPathKind {
    Direct,
    Relay,
    Unknown,
}

#[derive(Clone, Copy)]
struct IrohPath {
    selected: bool,
    kind: IrohPathKind,
}

fn connection_type_from_paths(paths: impl IntoIterator<Item = IrohPath>) -> Option<ConnectionType> {
    let mut direct = false;
    let mut relay = false;
    for path in paths {
        if path.selected {
            direct |= matches!(path.kind, IrohPathKind::Direct);
            relay |= matches!(path.kind, IrohPathKind::Relay);
        }
    }

    match (direct, relay) {
        (true, true) => Some(ConnectionType::Mixed),
        (true, false) => Some(ConnectionType::Direct),
        (false, true) => Some(ConnectionType::Relay),
        (false, false) => None,
    }
}
