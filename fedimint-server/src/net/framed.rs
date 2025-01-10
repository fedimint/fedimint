//! Adapter that implements a message based protocol on top of a stream based
//! one
use std::fmt::Debug;
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, BytesMut};
use fedimint_logging::LOG_NET_PEER;
use futures::{Sink, Stream};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::TlsStream;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{error, trace};

/// Owned [`FramedTransport`] trait object
pub type AnyFramedTransport<M> = Box<dyn FramedTransport<M> + Send + Unpin + 'static>;

/// A bidirectional framed transport adapter that can be split into its read and
/// write half
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

/// Sink (sending) half of [`BidiFramed`]
pub type FramedSink<S, T> = FramedWrite<S, BincodeCodec<T>>;
/// Stream (receiving) half of [`BidiFramed`]
pub type FramedStream<S, T> = FramedRead<S, BincodeCodec<T>>;

/// Framed transport codec for streams
///
/// Wraps a stream `S` and allows sending packetized data of type `T` over it.
/// Data items are encoded using [`bincode`] and the bytes are sent over the
/// stream prepended with a length field. `BidiFramed` implements `Sink<T>` and
/// `Stream<Item=Result<T, _>>`.
#[derive(Debug)]
pub struct BidiFramed<T> {
    sink: FramedSink<WriteHalf<TlsStream<TcpStream>>, T>,
    stream: FramedStream<ReadHalf<TlsStream<TcpStream>>, T>,
}

/// Framed codec that uses [`bincode`] to encode structs with [`serde`] support
#[derive(Debug)]
pub struct BincodeCodec<T> {
    _pd: PhantomData<T>,
}

impl<T> BidiFramed<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    pub fn new(stream: TlsStream<tokio::net::TcpStream>) -> BidiFramed<T> {
        let (read, write) = tokio::io::split(stream);

        BidiFramed {
            sink: FramedSink::new(write, BincodeCodec::new()),
            stream: FramedStream::new(read, BincodeCodec::new()),
        }
    }

    /// Splits the codec in its sending and receiving parts
    ///
    /// This can be useful in cases where potentially simultaneous read and
    /// write operations are required. Otherwise a we would need a mutex to
    /// guard access.
    pub fn borrow_parts(
        &mut self,
    ) -> (
        &mut FramedSink<WriteHalf<TlsStream<TcpStream>>, T>,
        &mut FramedStream<ReadHalf<TlsStream<TcpStream>>, T>,
    ) {
        (&mut self.sink, &mut self.stream)
    }
}

impl<T> Sink<T> for BidiFramed<T>
where
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

impl<T> Stream for BidiFramed<T>
where
    T: serde::de::DeserializeOwned,
{
    type Item = Result<T, anyhow::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Stream::poll_next(Pin::new(&mut self.stream), cx)
    }
}

impl<T> FramedTransport<T> for BidiFramed<T>
where
    T: Debug + serde::Serialize + serde::de::DeserializeOwned + Send,
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
        BincodeCodec { _pd: PhantomData }
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
        bincode::serialize_into(dst.writer(), &item).inspect_err(|_e| {
            error!(
                target: LOG_NET_PEER,
                "Serializing message failed: {:?}", item
            );
        })?;

        // Lastly we update the length field by counting how many bytes have been
        // written
        let new_len = dst.len();
        let encoded_len = new_len - old_len - 8;
        dst[old_len..old_len + 8].copy_from_slice(&encoded_len.to_be_bytes()[..]);

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

        let length = u64::from_be_bytes(src[0..8].try_into().expect("correct length"));
        if src.len() < (length as usize) + 8 {
            trace!(length, buffern_len = src.len(), "Received partial message");
            return Ok(None);
        }
        trace!(length, "Received full message");

        src.reader()
            .read_exact(&mut [0u8; 8][..])
            .expect("minimum length checked");

        Ok(bincode::deserialize_from(src.reader()).map(Option::Some)?)
    }
}
