use futures::{AsyncRead, AsyncWrite};
use futures::{Sink, Stream};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::Error;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use tracing::{debug, trace};

pub struct Framed<S, T> {
    stream: S,
    write_buffer: Vec<u8>,
    read_len_len: usize,
    read_len_buffer: [u8; 8],
    read_len_actual: usize,
    read_buffer: Vec<u8>,
    _phantom: PhantomData<T>,
}

impl<S, T> Framed<S, T>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: Serialize + DeserializeOwned + Unpin,
{
    pub fn new(stream: S) -> Self {
        Framed {
            stream,
            write_buffer: Vec::new(),
            read_len_len: 0,
            read_len_buffer: [0u8; 8],
            read_len_actual: 0,
            read_buffer: Vec::new(),
            _phantom: PhantomData,
        }
    }
}

impl<S, T> Sink<&T> for Framed<S, T>
where
    S: AsyncWrite + Unpin,
    T: Serialize + Unpin,
{
    type Error = FrameError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut_self = self.get_mut();

        if mut_self.write_buffer.is_empty() {
            return Poll::Ready(Ok(()));
        }

        match Pin::new(&mut mut_self.stream).poll_write(cx, &mut_self.write_buffer) {
            Poll::Ready(Ok(len)) => mut_self.write_buffer = mut_self.write_buffer[len..].to_vec(),
            Poll::Ready(Err(e)) => return Poll::Ready(Err(FrameError::IOError(e))),
            Poll::Pending => return Poll::Pending,
        };

        if mut_self.write_buffer.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn start_send(self: Pin<&mut Self>, item: &T) -> Result<(), Self::Error> {
        match bincode::serialize(item) {
            Ok(encoded) => {
                let mut frame = Vec::with_capacity(encoded.len() + 8);
                frame.extend_from_slice(&encoded.len().to_be_bytes());
                frame.extend_from_slice(&encoded);
                debug!("Sending  {} bytes", encoded.len());
                trace!("Sending  {:x?}", encoded);
                self.get_mut().write_buffer = frame;
                Ok(())
            }
            Err(e) => Err(FrameError::CodingError(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Sink::<&T>::poll_ready(self, cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Sink::<&T>::poll_ready(self, cx)
    }
}

impl<S, T> Stream for Framed<S, T>
where
    S: AsyncRead + Unpin,
    T: DeserializeOwned + Unpin,
{
    type Item = Result<T, FrameError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut_self = self.get_mut();

        if mut_self.read_len_len != 8 {
            match Pin::new(&mut mut_self.stream)
                .poll_read(cx, &mut mut_self.read_len_buffer[mut_self.read_len_len..])
            {
                Poll::Ready(Ok(len)) => {
                    mut_self.read_len_len += len;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(FrameError::IOError(e)))),
                Poll::Pending => return Poll::Pending,
            }
        }

        if mut_self.read_len_len == 8 {
            let exp_len = u64::from_be_bytes(mut_self.read_len_buffer) as usize;
            if exp_len != mut_self.read_buffer.len() {
                mut_self.read_buffer = vec![0; exp_len as usize];
            }

            if exp_len > mut_self.read_len_actual {
                match Pin::new(&mut mut_self.stream)
                    .poll_read(cx, &mut mut_self.read_buffer[mut_self.read_len_actual..])
                {
                    Poll::Ready(Ok(len)) => {
                        mut_self.read_len_actual += len;
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(FrameError::IOError(e)))),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if exp_len == mut_self.read_len_actual {
                debug!("Received {} bytes", exp_len);
                trace!("Received {:x?}", mut_self.read_buffer);
                let res = match bincode::deserialize(&mut_self.read_buffer) {
                    Ok(decoded) => Ok(decoded),
                    Err(e) => Err(FrameError::CodingError(e)),
                };

                mut_self.read_len_len = 0;
                mut_self.read_len_actual = 0;

                return Poll::Ready(Some(res));
            }
        }

        Poll::Pending
    }
}

#[derive(Debug)]
pub enum FrameError {
    CodingError(bincode::Error),
    IOError(std::io::Error),
}

impl From<bincode::Error> for FrameError {
    fn from(e: bincode::Error) -> Self {
        FrameError::CodingError(e)
    }
}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        FrameError::IOError(e)
    }
}
