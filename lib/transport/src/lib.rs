mod tcp;
mod udp;

use tokio::io;

/// Trait for transport mechanisms.
pub trait Transport {
    /// Sends data over the transport.
    async fn send(&mut self, data: &[u8]) -> io::Result<()>;

    /// Receives data from the transport.
    async fn receive(&mut self, data: &mut [u8]) -> io::Result<usize>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
