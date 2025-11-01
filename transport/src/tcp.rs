use std::net::SocketAddr;
use tokio::io;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use crate::Transport;

pub struct TcpStreamTransport {
    send_half: OwnedWriteHalf,
    recv_half: OwnedReadHalf,
}
impl TcpStreamTransport {
    pub async fn connect(remote_addr: &SocketAddr) -> io::Result<Self> {
        let stream = TcpStream::connect(remote_addr).await?;
        let (recv_half, send_half) = stream.into_split();

        Ok(TcpStreamTransport {
            recv_half,
            send_half,
        })
    }
}

impl Transport for TcpStreamTransport {
    async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        let size = data.len();
        let bytes_sent = 0;
        loop {
            let n = {
                self.send_half.writable().await?;
                self.send_half.try_write(data)?
            };

            if n + bytes_sent == size {
                break;
            }
        }

        Ok(())
    }

    async fn receive(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_half.readable().await?;
        self.recv_half.try_read(buf)
    }
}
