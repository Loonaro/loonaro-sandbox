use crate::Transport;
use std::net::SocketAddr;
use tokio::io;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

pub struct TcpStreamTransport {
    send_half: OwnedWriteHalf,
    recv_half: OwnedReadHalf,
}
impl TcpStreamTransport {
    pub async fn connect(remote_addr: &SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(remote_addr).await?;
        Ok(stream.into())
    }
}
impl From<TcpStream> for TcpStreamTransport {
    fn from(value: TcpStream) -> Self {
        let (recv_half, send_half) = value.into_split();

        Self {
            recv_half,
            send_half,
        }
    }
}

impl Transport for TcpStreamTransport {
    async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        let mut offset = 0;
        let size = data.len();

        while offset < size {
            self.send_half.writable().await?;
            match self.send_half.try_write(&data[offset..]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "failed to write to socket")),
                Ok(n) => offset += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // try again after becoming writable
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        Ok(())
    }

    async fn receive(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            self.recv_half.readable().await?;
            match self.recv_half.try_read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // try again after becoming readable
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}
