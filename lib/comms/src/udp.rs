use std::net::SocketAddr;
use tokio::io;
use tokio::net::UdpSocket;
use crate::Transport;

pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub async fn connect(remote_addr: &SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(remote_addr).await?;

        Ok(UdpTransport { socket })
    }
}

impl Transport for UdpTransport {
    async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        let size = data.len();
        let mut bytes_sent = 0;
        while bytes_sent < size {
            self.socket.writable().await?;
            let n = match self.socket.send(data).await {
                Ok(n) => n,
                Err(e) => {
                    if e.kind() == io::ErrorKind::WouldBlock {
                        continue;
                    }

                    return Err(e);
                }
            };
            
            bytes_sent += n;
        }

        Ok(())
    }

    async fn receive(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.readable().await?;
        self.socket.recv(buf).await
    }
}
