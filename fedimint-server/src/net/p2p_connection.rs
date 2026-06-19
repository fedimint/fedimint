use std::io::Cursor;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_server_core::dashboard_ui::ConnectionPaths;
use futures::{SinkExt, StreamExt};
use iroh_next::endpoint::{Connection, RecvStream};
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

    /// Get the transport paths (direct and/or relayed) currently backing the
    /// connection, for reporting on the guardian dashboard.
    fn connection_paths(&self) -> Option<ConnectionPaths>;

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

    fn connection_paths(&self) -> Option<ConnectionPaths> {
        // TLS connections are always a direct TCP connection, never relayed.
        Some(ConnectionPaths {
            direct: true,
            relay: false,
        })
    }
}

/// Implementations of the IP2PFrame and IP2PConnection traits for Iroh

#[async_trait]
impl<M> IP2PFrame<M> for RecvStream
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
impl<M> IP2PConnection<M> for Connection
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
        // iroh 1.0 reports RTT per path; use the currently selected one.
        self.paths()
            .iter()
            .find(iroh_next::endpoint::Path::is_selected)
            .and_then(|path| Connection::rtt(self, path.id()))
    }

    fn connection_paths(&self) -> Option<ConnectionPaths> {
        // iroh 1.0 exposes path information per connection; report whether any
        // direct (IP) and/or relayed path is currently available.
        let mut direct = false;
        let mut relay = false;
        for path in self.paths().iter() {
            direct |= path.is_ip();
            relay |= path.is_relay();
        }

        Some(ConnectionPaths { direct, relay })
    }
}
