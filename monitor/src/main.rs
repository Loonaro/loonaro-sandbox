use anyhow::Context;
use comms::tcp::TcpStreamTransport;
use comms::{Message, Transport};
use etw::{EtwEvent, Event, EventPayload, ProcessEvent};
use minicbor::{Decode, Decoder};
use std::net::SocketAddr;
use std::str::FromStr;
use thiserror::Error;
use comfy_table::{presets, Attribute, Cell, Color, ContentArrangement, Row, Table};
use terminal_size::{terminal_size, Width};

#[derive(Error, Debug)]
pub enum MonitorError {
    #[error("Failed to parse agent address: {0}")]
    AgentConnectionFailed(#[from] std::net::AddrParseError),

    #[error("Failed to connect to agent: {0}")]
    AgentConnectionError(#[from] tokio::io::Error),
}

enum ReadState {
    ExpectHeader,
    ExpectPayload {
        size: usize,
        header: Option<etw::EventHeader>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Connect to the agent on the port used by the agent (see agent/src/main.rs)
    let agent_addr = SocketAddr::from_str("127.0.0.1:1337")?;
    let mut transport = TcpStreamTransport::connect(&agent_addr)
        .await
        .context("Failed to connect to agent")?;

    let mut collected_events = Vec::with_capacity(1024);
    collect(&mut transport, &mut collected_events).await?;

    print_events(&mut collected_events);

    Ok(())
}

fn print_events(collected_events: &mut Vec<Event>) {
    let mut table = Table::new();
    table.load_preset(presets::UTF8_FULL);
    table.set_content_arrangement(ContentArrangement::Dynamic);

    if let Some((Width(w), _)) = terminal_size() {
        // Bound width to something reasonable to avoid super-wide tables on huge terminals
        let width = w as usize;
        let max_width = width.min(200);
        table.set_width(max_width as u16);
    }

    table.set_header(Row::from(vec![
        Cell::new("Event").add_attribute(Attribute::Bold).fg(Color::Green),
        Cell::new("Timestamp").add_attribute(Attribute::Bold).fg(Color::Cyan),
        Cell::new("PID").add_attribute(Attribute::Bold),
        Cell::new("PPID").add_attribute(Attribute::Bold),
        Cell::new("SessionID").add_attribute(Attribute::Bold),
        Cell::new("ExitStatus").add_attribute(Attribute::Bold),
        Cell::new("DTB").add_attribute(Attribute::Bold),
        Cell::new("ImageName").add_attribute(Attribute::Bold),
        Cell::new("CommandLine").add_attribute(Attribute::Bold),
    ]));

    for event in collected_events.iter() {
        match event.payload() {
            EventPayload::Process(proc_event) => {
                let (etype_text, etype_color) = match event.header().event_type() {
                    EtwEvent::SystemProcess(e) => match e {
                        ProcessEvent::ProcessCreate => ("ProcessCreate", Color::Green),
                        ProcessEvent::ProcessTerminate => ("ProcessTerminate", Color::Red),
                    },
                    EtwEvent::Sysmon => ("Sysmon", Color::Yellow),
                };

                let ts = event.header().timestamp();
                let pid = proc_event.pid();
                let ppid = proc_event.ppid();
                let session_id = proc_event.session_id();
                let exit_status = proc_event.exit_status();
                let dtb = proc_event.directory_table_base();
                let image_name = proc_event.image();
                let command_line = proc_event.cmd();

                table.add_row(Row::from(vec![
                    Cell::new(etype_text).fg(etype_color),
                    Cell::new(format!("{}", ts)).fg(Color::Cyan),
                    Cell::new(format!("{}", pid)),
                    Cell::new(format!("{}", ppid)),
                    Cell::new(format!("{}", session_id)),
                    Cell::new(format!("{}", exit_status)),
                    Cell::new(format!("{}", dtb)),
                    Cell::new(image_name),
                    Cell::new(command_line),
                ]));
            }
        }
    }

    println!("{}", table);
}

async fn collect(
    transport: &mut TcpStreamTransport,
    all_events: &mut Vec<Event>,
) -> anyhow::Result<()> {

    // Stream parsing state
    let mut inbox: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut state = ReadState::ExpectHeader;

    // Temporary read buffer
    let mut buf = vec![0u8; 16 * 1024];

    loop {
        // Read some bytes from the socket
        let n = transport
            .receive(&mut buf)
            .await
            .context("Failed to receive events")?;
        if n == 0 {
                        return Err(anyhow::anyhow!("Connection closed by peer"));
        }
        inbox.extend_from_slice(&buf[..n]);

        // Process as much as possible from the inbox
        let mut made_progress = true;
        while made_progress {
            made_progress = false;
            match &mut state {
                ReadState::ExpectHeader => {
                    let mut dec = Decoder::new(&inbox);
                    match Message::decode(&mut dec, &mut ()) {
                        Ok(message) => {
                            let consumed = dec.position();
                            // Drop the consumed bytes
                            inbox.drain(0..consumed);

                            match message {
                                Message::EventHeader(header, payload_size) => {
                                    state = ReadState::ExpectPayload {
                                        size: payload_size as usize,
                                        header: Some(header),
                                    };
                                }
                                Message::TracingFinished(n) => {
                                    println!(
                                        "Tracing finished. Total events received: {}",
                                        all_events.len()
                                    );

                                    let events_dropped = n as isize - all_events.len() as isize;
                                    if events_dropped > 0 {
                                        eprintln!(
                                            "Warning: {} events were traced but not received",
                                            events_dropped
                                        );
                                    }
                                    return Ok(());
                                }
                            }
                            made_progress = true;
                        }
                        Err(e) => {
                            // If we don't have enough bytes to decode a full CBOR message yet, wait for more.
                            let msg = e.to_string();
                            if msg.contains("end of input") || msg.contains("unexpected EOF") {
                                // Need more data
                                break;
                            } else {
                                // Corrupted stream or desync. Log and try to resync by dropping one byte.
                                eprintln!("Failed to decode message: {}", e);
                                // Avoid infinite loop on empty inbox
                                if !inbox.is_empty() {
                                    inbox.drain(0..1);
                                    made_progress = true;
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                }
                ReadState::ExpectPayload { size, header } => {
                    if inbox.len() < *size {
                        // Wait for more bytes
                        break;
                    }

                    // Extract exactly the payload bytes
                    let payload: Vec<u8> = inbox.drain(0..*size).collect();

                    // Take ownership of the header
                    let hdr = match header.take() {
                        Some(h) => h,
                        None => {
                            eprintln!("Missing header for payload; resetting state");
                            state = ReadState::ExpectHeader;
                            made_progress = true;
                            continue;
                        }
                    };

                    // Decode the event payload
                    match hdr.event_type() {
                        EtwEvent::SystemProcess(_) => {
                            let process_event = match etw::payload::process::ProcessEventPayload::parse(&payload) {
                                Ok(ev) => ev,
                                Err(e) => {
                                    eprintln!("Failed to parse process event payload: {}", e);
                                    // After an error, reset to ExpectHeader to try to continue
                                    state = ReadState::ExpectHeader;
                                    made_progress = true;
                                    continue;
                                }
                            };

                            let event = Event::new(hdr, EventPayload::Process(process_event));
                            all_events.push(event);
                        }
                        EtwEvent::Sysmon => {
                            eprintln!("Sysmon events are not yet supported");
                        }
                    }

                    // After handling the payload, go back to expecting a header
                    state = ReadState::ExpectHeader;
                    made_progress = true;
                }
            }
        }
    }
}
