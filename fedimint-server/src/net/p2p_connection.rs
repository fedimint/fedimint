use std::fmt::Debug;
use std::io::Cursor;

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::TlsStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub type DynP2PConnection<M> = Box<dyn IP2PConnection<M>>;

#[async_trait]
pub trait IP2PConnection<M>: Send + 'static {
    async fn send(&mut self, message: M) -> anyhow::Result<()>;

    async fn receive(&mut self) -> anyhow::Result<M>;

    fn into_dyn(self) -> DynP2PConnection<M>
    where
        Self: Sized,
    {
        Box::new(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LegacyMessage<M> {
    Message(M),
    Ping,
}

#[async_trait]
impl<M> IP2PConnection<M> for Framed<TlsStream<TcpStream>, LengthDelimitedCodec>
where
    M: Serialize + DeserializeOwned + Send + 'static,
{
    async fn send(&mut self, message: M) -> anyhow::Result<()> {
        let mut bytes = Vec::new();

        bincode::serialize_into(&mut bytes, &LegacyMessage::Message(message))?;

        SinkExt::send(self, Bytes::from_owner(bytes)).await?;

        Ok(())
    }

    async fn receive(&mut self) -> anyhow::Result<M> {
        loop {
            let bytes = self.next().await.context("Framed stream is closed")??;

            if let Ok(legacy_message) = bincode::deserialize_from(Cursor::new(&bytes)) {
                match legacy_message {
                    LegacyMessage::Message(message) => return Ok(message),
                    LegacyMessage::Ping => continue,
                }
            }

            return Ok(bincode::deserialize_from(Cursor::new(&bytes))?);
        }
    }
}

#[cfg(all(feature = "enable_iroh", not(target_family = "wasm")))]
pub mod iroh {
    use async_trait::async_trait;
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use iroh::endpoint::Connection;

    use crate::net::p2p_connection::IP2PConnection;

    #[async_trait]
    impl<M> IP2PConnection<M> for Connection
    where
        M: Encodable + Decodable + Send + 'static,
    {
        async fn send(&mut self, message: M) -> anyhow::Result<()> {
            let mut sink = self.open_uni().await?;

            sink.write_all(&message.consensus_encode_to_vec()).await?;

            sink.finish()?;

            Ok(())
        }

        async fn receive(&mut self) -> anyhow::Result<M> {
            let bytes = self.accept_uni().await?.read_to_end(1_000_000_000).await?;

            Ok(Decodable::consensus_decode_whole(
                &bytes,
                &ModuleDecoderRegistry::default(),
            )?)
        }
    }
}
