use std::fmt::Debug;
use std::io::Cursor;
use std::marker::PhantomData;

use anyhow::Context;
use async_trait::async_trait;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use iroh::endpoint::Connection;
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::net::TcpStream;
use tokio_rustls::TlsStream;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub type DynFramedTransport<M> = Box<dyn FramedTransport<M>>;

#[async_trait]
pub trait FramedTransport<T>: Send + 'static {
    async fn send(&mut self, message: T) -> anyhow::Result<()>;

    async fn receive(&mut self) -> anyhow::Result<T>;

    fn into_dyn(self) -> DynFramedTransport<T>
    where
        Self: Sized,
    {
        Box::new(self)
    }
}

#[derive(Debug)]
pub struct FramedTlsTcpStream<T> {
    stream: Framed<TlsStream<TcpStream>, LengthDelimitedCodec>,
    _pd: PhantomData<T>,
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

#[async_trait]
impl<T> FramedTransport<T> for FramedTlsTcpStream<T>
where
    T: Serialize + DeserializeOwned + Send + 'static,
{
    async fn send(&mut self, message: T) -> anyhow::Result<()> {
        let mut bytes = Vec::new();

        bincode::serialize_into(&mut bytes, &message)?;

        self.stream.send(Bytes::from_owner(bytes)).await?;

        Ok(())
    }

    async fn receive(&mut self) -> anyhow::Result<T> {
        let bytes = self
            .stream
            .next()
            .await
            .context("Framed stream is closed")??;

        Ok(bincode::deserialize_from(Cursor::new(&bytes))?)
    }
}

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
impl<M> FramedTransport<M> for IrohConnection<M>
where
    M: Serialize + DeserializeOwned + Send + 'static,
{
    async fn send(&mut self, message: M) -> anyhow::Result<()> {
        let mut bytes = Vec::new();

        bincode::serialize_into(&mut bytes, &message)?;

        let mut sink = self.connection.open_uni().await?;

        sink.write_all(&bytes).await?;

        sink.finish()?;

        Ok(())
    }

    async fn receive(&mut self) -> anyhow::Result<M> {
        let bytes = self
            .connection
            .accept_uni()
            .await?
            .read_to_end(100_000)
            .await?;

        Ok(bincode::deserialize_from(Cursor::new(&bytes))?)
    }
}
