use bytes::{Buf, BufMut, BytesMut};
use prost::Message;
use std::io;
use tokio_util::codec::{Decoder, Encoder};

// Max frame size (e.g., 64MB for screenshots/dumps)
const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

pub struct ProtoCodec<In, Out> {
    _phantom_in: std::marker::PhantomData<In>,
    _phantom_out: std::marker::PhantomData<Out>,
}

impl<In, Out> ProtoCodec<In, Out> {
    pub fn new() -> Self {
        Self {
            _phantom_in: std::marker::PhantomData,
            _phantom_out: std::marker::PhantomData,
        }
    }
}

impl<In, Out> Decoder for ProtoCodec<In, Out>
where
    In: Message + Default,
{
    type Item = In;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            return Ok(None);
        }

        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let length = u32::from_be_bytes(length_bytes) as usize;

        if length > MAX_FRAME_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Frame of length {} exceeds max allowed {}",
                    length, MAX_FRAME_SIZE
                ),
            ));
        }

        if src.len() < 4 + length {
            src.reserve(4 + length - src.len());
            return Ok(None);
        }

        src.advance(4);
        let data = src.split_to(length);

        In::decode(data)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

impl<In, Out> Encoder<Out> for ProtoCodec<In, Out>
where
    Out: Message,
{
    type Error = io::Error;

    fn encode(&mut self, item: Out, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let len = item.encoded_len();
        dst.reserve(4 + len);
        dst.put_u32(len as u32);
        item.encode(dst)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

/// abstraction for a bidirectional protobuf connection
/// S: Transport (TcpStream, etc)
/// In: Message Type to Receive
/// Out: Message Type to Send
pub struct Connection<S, In, Out> {
    framed: Framed<S, ProtoCodec<In, Out>>,
}

impl<S, In, Out> Connection<S, In, Out>
where
    S: AsyncRead + AsyncWrite + Unpin,
    In: Message + Default,
    Out: Message,
{
    pub fn new(stream: S) -> Self {
        Self {
            framed: Framed::new(stream, ProtoCodec::new()),
        }
    }

    pub async fn send(&mut self, msg: Out) -> io::Result<()> {
        self.framed.send(msg).await
    }

    pub async fn recv(&mut self) -> Option<io::Result<In>> {
        self.framed.next().await
    }

    pub fn split(
        self,
    ) -> (
        ConnectionWriter<futures::stream::SplitSink<Framed<S, ProtoCodec<In, Out>>, Out>, Out>,
        ConnectionReader<futures::stream::SplitStream<Framed<S, ProtoCodec<In, Out>>>, In>,
    ) {
        let (sink, stream) = self.framed.split();
        (
            ConnectionWriter {
                sink,
                _phantom: std::marker::PhantomData,
            },
            ConnectionReader {
                stream,
                _phantom: std::marker::PhantomData,
            },
        )
    }
}

pub struct ConnectionWriter<S, Out> {
    sink: S,
    _phantom: std::marker::PhantomData<Out>,
}

impl<S, Out> ConnectionWriter<S, Out>
where
    S: futures::Sink<Out, Error = io::Error> + Unpin,
{
    pub async fn send(&mut self, msg: Out) -> io::Result<()> {
        self.sink.send(msg).await
    }
}

pub struct ConnectionReader<S, In> {
    stream: S,
    _phantom: std::marker::PhantomData<In>,
}

impl<S, In> ConnectionReader<S, In>
where
    S: futures::Stream<Item = Result<In, io::Error>> + Unpin,
{
    pub async fn recv(&mut self) -> Option<io::Result<In>> {
        self.stream.next().await
    }
}
