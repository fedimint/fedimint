//! Adapter that implements a message based protocol on top of a stream based one
use std::convert::TryInto;
use std::fmt::Debug;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, BytesMut};
use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{error, trace};

/// Owned [`FramedTransport`] trait object
pub type AnyFramedTransport<M> = Box<dyn FramedTransport<M> + Send + Unpin + 'static>;

/// A bidirectional framed transport adapter that can be split into its read and write half
pub trait FramedTransport<T>:
    Sink<T, Error = anyhow::Error> + Stream<Item = Result<T, anyhow::Error>>
{
    /// Split the framed transport into read and write half
    fn borrow_split(
        &mut self,
    ) -> (
        &'_ mut (dyn Sink<T, Error = anyhow::Error> + Send + Unpin),
        &'_ mut (dyn Stream<Item = Result<T, anyhow::Error>> + Send + Unpin),
    );

    /// Transforms concrete `FramedTransport` object into an owned trait object
    fn into_dyn(self) -> AnyFramedTransport<T>
    where
        Self: Sized + Send + Unpin + 'static,
    {
        Box::new(self)
    }
}

/// Special case for tokio [`TcpStream`](tokio::net::TcpStream) based [`BidiFramed`] instances
pub type TcpBidiFramed<T> = BidiFramed<T, OwnedWriteHalf, OwnedReadHalf>;

/// Sink (sending) half of [`BidiFramed`]
pub type FramedSink<S, T> = FramedWrite<S, BincodeCodec<T>>;
/// Stream (receiving) half of [`BidiFramed`]
pub type FramedStream<S, T> = FramedRead<S, BincodeCodec<T>>;

/// Framed transport codec for streams
///
/// Wraps a stream `S` and allows sending packetized data of type `T` over it. Data items are
/// encoded using [`bincode`] and the bytes are sent over the stream prepended with a length field.
/// `BidiFramed` implements `Sink<T>` and `Stream<Item=Result<T, _>>`.
#[derive(Debug)]
pub struct BidiFramed<T, WH, RH> {
    sink: FramedSink<WH, T>,
    stream: FramedStream<RH, T>,
}

/// Framed codec that uses [`bincode`] to encode structs with [`serde`] support
#[derive(Debug)]
pub struct BincodeCodec<T> {
    _pd: PhantomData<T>,
}

impl<T, WH, RH> BidiFramed<T, WH, RH>
where
    WH: AsyncWrite,
    RH: AsyncRead,
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    /// Builds a new `BidiFramed` codec around a stream `stream`.
    ///
    /// See [`TcpBidiFramed::new_from_tcp`] for a more efficient version in case the stream is a tokio TCP stream.
    pub fn new<S>(stream: S) -> BidiFramed<T, WriteHalf<S>, ReadHalf<S>>
    where
        S: AsyncRead + AsyncWrite,
    {
        let (read, write) = tokio::io::split(stream);
        BidiFramed {
            sink: FramedSink::new(write, BincodeCodec::new()),
            stream: FramedStream::new(read, BincodeCodec::new()),
        }
    }

    /// Splits the codec in its sending and receiving parts
    ///
    /// This can be useful in cases where potentially simultaneous read and write operations are
    /// required. Otherwise a we would need a mutex to guard access.
    pub fn borrow_parts(&mut self) -> (&mut FramedSink<WH, T>, &mut FramedStream<RH, T>) {
        (&mut self.sink, &mut self.stream)
    }
}

impl<T> TcpBidiFramed<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    /// Special constructor for tokio TCP connections.
    ///
    /// Tokio [`TcpStream`](tokio::net::TcpStream) implements an efficient method of splitting the
    /// stream into a read and a write half this constructor takes advantage of.
    pub fn new_from_tcp(stream: tokio::net::TcpStream) -> TcpBidiFramed<T> {
        let (read, write) = stream.into_split();
        BidiFramed {
            sink: FramedSink::new(write, BincodeCodec::new()),
            stream: FramedStream::new(read, BincodeCodec::new()),
        }
    }
}

impl<T, WH, RH> Sink<T> for BidiFramed<T, WH, RH>
where
    WH: tokio::io::AsyncWrite + Unpin,
    RH: Unpin,
    T: Debug + serde::Serialize,
{
    type Error = anyhow::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Sink::poll_ready(Pin::new(&mut self.sink), cx)
    }

    fn start_send(mut self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        Sink::start_send(Pin::new(&mut self.sink), item)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Sink::poll_flush(Pin::new(&mut self.sink), cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Sink::poll_close(Pin::new(&mut self.sink), cx)
    }
}

impl<T, WH, RH> Stream for BidiFramed<T, WH, RH>
where
    T: serde::de::DeserializeOwned,
    WH: Unpin,
    RH: tokio::io::AsyncRead + Unpin,
{
    type Item = Result<T, anyhow::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Stream::poll_next(Pin::new(&mut self.stream), cx)
    }
}

impl<T, WH, RH> FramedTransport<T> for BidiFramed<T, WH, RH>
where
    T: Debug + serde::Serialize + serde::de::DeserializeOwned + Send,
    WH: tokio::io::AsyncWrite + Send + Unpin,
    RH: tokio::io::AsyncRead + Send + Unpin,
{
    fn borrow_split(
        &mut self,
    ) -> (
        &'_ mut (dyn Sink<T, Error = anyhow::Error> + Send + Unpin),
        &'_ mut (dyn Stream<Item = Result<T, anyhow::Error>> + Send + Unpin),
    ) {
        let (sink, stream) = self.borrow_parts();
        (&mut *sink, &mut *stream)
    }
}

impl<T> BincodeCodec<T> {
    fn new() -> BincodeCodec<T> {
        BincodeCodec {
            _pd: Default::default(),
        }
    }
}

impl<T> tokio_util::codec::Encoder<T> for BincodeCodec<T>
where
    T: serde::Serialize + Debug,
{
    type Error = anyhow::Error;

    fn encode(&mut self, item: T, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        // First, write a dummy length field and remember its position
        let old_len = dst.len();
        dst.writer().write_all(&[0u8; 8]).unwrap();
        assert_eq!(dst.len(), old_len + 8);

        // Then we serialize the message into the buffer
        bincode::serialize_into(dst.writer(), &item).map_err(|e| {
            error!("Serializing message failed: {:?}", item);
            e
        })?;

        // Lastly we update the length field by counting how many bytes have been written
        let new_len = dst.len();
        let encoded_len = new_len - old_len - 8;
        dst[old_len..old_len + 8].copy_from_slice(&encoded_len.to_le_bytes()[..]);

        Ok(())
    }
}

impl<T> tokio_util::codec::Decoder for BincodeCodec<T>
where
    T: serde::de::DeserializeOwned,
{
    type Item = T;
    type Error = anyhow::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 8 {
            return Ok(None);
        }

        let length = u64::from_le_bytes(src[0..8].try_into().expect("correct length"));
        if src.len() < (length as usize) + 8 {
            trace!(length, buffern_len = src.len(), "Received partial message");
            return Ok(None);
        } else {
            trace!(length, "Received full message");
        }

        src.reader()
            .read_exact(&mut [0u8; 8][..])
            .expect("minimum length checked");

        Ok(bincode::deserialize_from(src.reader()).map(Option::Some)?)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use futures::{SinkExt, StreamExt};
    use serde::{Deserialize, Serialize};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

    use crate::net::framed::BidiFramed;

    #[tokio::test]
    async fn test_roundtrip() {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
        enum TestEnum {
            Foo,
            Bar(u64),
        }

        let input = vec![TestEnum::Foo, TestEnum::Bar(42), TestEnum::Foo];
        let (sender, recipient) = tokio::io::duplex(1024);

        let mut framed_sender =
            BidiFramed::<TestEnum, WriteHalf<DuplexStream>, ReadHalf<DuplexStream>>::new(sender);

        let mut framed_recipient =
            BidiFramed::<TestEnum, WriteHalf<DuplexStream>, ReadHalf<DuplexStream>>::new(recipient);

        for item in &input {
            framed_sender.send(item.clone()).await.unwrap();
        }

        for item in &input {
            let received = framed_recipient.next().await.unwrap().unwrap();
            assert_eq!(&received, item);
        }
        drop(framed_sender);

        assert!(framed_recipient.next().await.is_none());
    }

    #[tokio::test]
    async fn test_not_try_parse_partial() {
        #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
        enum TestEnum {
            Foo,
            Bar(u64),
        }

        let (sender_src, mut recipient_src) = tokio::io::duplex(1024);
        let (mut sender_dst, recipient_dst) = tokio::io::duplex(1024);

        let mut framed_sender =
            BidiFramed::<TestEnum, WriteHalf<DuplexStream>, ReadHalf<DuplexStream>>::new(
                sender_src,
            );
        let mut framed_recipient =
            BidiFramed::<TestEnum, WriteHalf<DuplexStream>, ReadHalf<DuplexStream>>::new(
                recipient_dst,
            );

        framed_sender
            .send(TestEnum::Bar(0x4242_4242_4242_4242))
            .await
            .unwrap();

        // Simulate a partial send
        let mut buf = [0u8; 3];
        recipient_src.read_exact(&mut buf).await.unwrap();
        sender_dst.write_all(&buf).await.unwrap();

        // Try to read, should not return an error but block
        let received = tokio::time::timeout(Duration::from_secs(1), framed_recipient.next()).await;

        assert!(received.is_err());
    }
}
