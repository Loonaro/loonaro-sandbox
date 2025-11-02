mod commandline;

use comms::{Message, Transport};
use etw::{EventHeader, ProcessEvent};
use one_collect::ReadOnly;
use one_collect::etw::AncillaryData;
use one_collect::event::EventData;
use one_collect::helpers::callstack::{CallstackHelp, CallstackHelper};
use std::cell::RefCell;
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use std::rc::Rc;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 1337));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("Listening on {addr}");

    let (stream, client_addr) = listener.accept().await.unwrap();
    println!("Accepted connection from {client_addr}");

    let mut transport = comms::tcp::TcpStreamTransport::from(stream);

    // Create a bounded channel for outbound messages.
    // Tune the capacity based on throughput/latency requirements.
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8192);

    // Spawn a task that owns the comms and drains the queue.
    let handle = tokio::spawn(async move {
        while let Some(buf) = rx.recv().await {
            if let Err(e) = transport.send(&buf).await {
                // If the connection breaks, we stop sending.
                eprintln!("comms send error: {e}");
                break;
            }
        }
    });

    do_etw(tx);

    handle.abort();
}

fn do_etw(tx: mpsc::Sender<Vec<u8>>) {
    let helper = CallstackHelper::new();
    let mut etw = one_collect::etw::EtwSession::new().with_callstack_help(&helper);

    let ancillary = etw.ancillary_data();
    let event = etw.comm_start_event();

    // The ETW callback is synchronous; we enqueue the serialized message without awaiting.
    let tx_clone = tx.clone();
    let ancillary_clone = ancillary.clone();

    // Also counting the number of events sent. so we can compare on host if any were dropped during transit.
    let events_sent = Rc::new(RefCell::new(0));
    let counter = events_sent.clone();

    event.add_callback(move |data| {
        send_event_enqueue(&tx_clone, data, &ancillary_clone)
            .map(|v| {
                *counter.borrow_mut() += 1;
                v
            })
            .into()
    });

    let duration = std::time::Duration::from_secs(15);
    etw.parse_for_duration("agent_process_test", duration)
        .unwrap();

    // Send end-of-tracing message
    let events_sent = events_sent.take();
    let end_buf = minicbor::to_vec(Message::TracingFinished(events_sent)).unwrap();
    let _ = tx.try_send(end_buf);

    println!("Finishing ETW tracing. Events sent: {}", events_sent);
}

fn send_event_enqueue(
    tx: &mpsc::Sender<Vec<u8>>,
    data: &EventData<'_>,
    ancillary: &ReadOnly<AncillaryData>,
) -> anyhow::Result<()> {
    let mut header = MaybeUninit::<EventHeader>::uninit();
    ancillary.read(|e| {
        header.write(EventHeader::from_ancillary(
            e,
            etw::EtwEvent::SystemProcess(ProcessEvent::ProcessCreate),
        ));
    });

    // Construct the message as: CBOR(header, payload_size) || payload
    let payload = data.event_data();
    let payload_size = payload.len() as u32; // max 64KB according to ETW docs

    // Try to enqueue without blocking; if failed to send, it's dropped.
    let message = Message::EventHeader(unsafe { header.assume_init() }, payload_size);
    match tx.try_send(minicbor::to_vec(message)?) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Failed to enqueue event message: {}", e);
        }
    }

    // Enqueue the payload
    match tx.try_send(payload.to_vec()) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Failed to enqueue event payload: {}", e);
        }
    }

    Ok(())
}
