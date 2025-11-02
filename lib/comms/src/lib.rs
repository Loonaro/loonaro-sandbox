pub mod tcp;
pub mod udp;

use etw::EventHeader;
use minicbor::{Decode, Encode};
use tokio::io;

#[derive(Encode, Decode, Debug)]
pub enum Message {
    /// After this message, the payload will follow as raw bytes of the specified length.
    #[n(0)]
    EventHeader(#[n(0)] EventHeader, #[n(1)] u32),
    /// This happens when the agent has finished tracing. Also gives the number of events sent.
    #[n(1)]
    TracingFinished(#[n(0)] u64),
}

/// Trait for comms mechanisms.
pub trait Transport {
    /// Sends data over the comms.
    fn send(&mut self, data: &[u8]) -> impl std::future::Future<Output = io::Result<()>> + Send;

    /// Receives data from the comms.
    fn receive(
        &mut self,
        data: &mut [u8],
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send;
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
