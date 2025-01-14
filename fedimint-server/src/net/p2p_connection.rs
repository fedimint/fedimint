use std::fmt::Debug;
use std::io::Cursor;
use std::marker::PhantomData;

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::TlsStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub type DynP2PConnection<M> = Box<dyn P2PConnection<M>>;

#[async_trait]
pub trait P2PConnection<M>: Send + 'static {
    async fn send(&mut self, message: M) -> anyhow::Result<()>;

    async fn receive(&mut self) -> anyhow::Result<M>;

    fn into_dyn(self) -> DynP2PConnection<M>
    where
        Self: Sized,
    {
        Box::new(self)
    }
}

#[derive(Debug)]
pub struct FramedTlsTcpStream<M> {
    stream: Framed<TlsStream<TcpStream>, LengthDelimitedCodec>,
    _pd: PhantomData<M>,
}

impl<T> FramedTlsTcpStream<T> {
    pub fn new(stream: TlsStream<TcpStream>) -> FramedTlsTcpStream<T> {
        FramedTlsTcpStream {
            stream: LengthDelimitedCodec::builder()
                .length_field_type::<u64>()
                .new_framed(stream),
            _pd: PhantomData,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LegacyMessage<M> {
    Message(M),
    Ping,
}

#[async_trait]
impl<M> P2PConnection<M> for FramedTlsTcpStream<M>
where
    M: Serialize + DeserializeOwned + Send + 'static,
{
    async fn send(&mut self, message: M) -> anyhow::Result<()> {
        let mut bytes = Vec::new();

        bincode::serialize_into(&mut bytes, &LegacyMessage::Message(message))?;

        self.stream.send(Bytes::from_owner(bytes)).await?;

        Ok(())
    }

    async fn receive(&mut self) -> anyhow::Result<M> {
        loop {
            let bytes = self
                .stream
                .next()
                .await
                .context("Framed stream is closed")??;

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
    use std::fmt::Debug;
    use std::marker::PhantomData;

    use async_trait::async_trait;
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleDecoderRegistry;
    use iroh::endpoint::Connection;

    use crate::net::p2p_connection::P2PConnection;

    #[derive(Debug)]
    pub struct IrohConnection<M> {
        connection: Connection,
        _pd: PhantomData<M>,
    }

    impl<M> IrohConnection<M> {
        pub fn new(connection: Connection) -> IrohConnection<M> {
            IrohConnection {
                connection,
                _pd: PhantomData,
            }
        }
    }

    #[async_trait]
    impl<M> P2PConnection<M> for IrohConnection<M>
    where
        M: Encodable + Decodable + Send + 'static,
    {
        async fn send(&mut self, message: M) -> anyhow::Result<()> {
            let mut sink = self.connection.open_uni().await?;

            sink.write_all(&message.consensus_encode_to_vec()).await?;

            sink.finish()?;

            Ok(())
        }

        async fn receive(&mut self) -> anyhow::Result<M> {
            let bytes = self
                .connection
                .accept_uni()
                .await?
                .read_to_end(1_000_000_000)
                .await?;

            Ok(Decodable::consensus_decode_whole(
                &bytes,
                &ModuleDecoderRegistry::default(),
            )?)
        }
    }
}
