use anyhow::{Context, Result};
use comms::{MemoryDumpHeader, Message, Transport};
use etw::{EtwEvent, Event, EventPayload};
use minicbor::{Decode, Decoder};
use rand::Rng;

use crate::artifacts::ArtifactCollector;
use crate::moose::{MalwareEvent, send_lifecycle, send_malware_event};

enum ReadState {
    ExpectHeader,
    ExpectPayload {
        size: usize,
        header: Option<etw::EventHeader>,
    },
    ExpectMemoryDumpPayload {
        size: usize,
        header: Option<MemoryDumpHeader>,
    },
}

pub async fn collect(
    transport: &mut impl Transport,
    all_events: &mut Vec<Event>,
    moose_url: &str,
    moose_key: &str,
    session_id: &str,
    artifact_collector: &mut ArtifactCollector,
) -> Result<()> {
    let mut inbox: Vec<u8> = Vec::with_capacity(64 * 1024);

    let mut state = ReadState::ExpectHeader;

    let mut buf = vec![0u8; 16 * 1024];

    loop {
        let n = transport
            .receive(&mut buf)
            .await
            .context("Failed to receive events")?;
        if n == 0 {
            return Err(anyhow::anyhow!("Connection closed by peer"));
        }
        inbox.extend_from_slice(&buf[..n]);

        loop {
            match &mut state {
                ReadState::ExpectHeader => {
                    let mut dec = Decoder::new(&inbox);
                    match Message::decode(&mut dec, &mut ()) {
                        Ok(message) => {
                            let consumed = dec.position();
                            inbox.drain(0..consumed);

                            if let Some(new_state) = handle_message(
                                message, all_events, moose_url, moose_key, session_id,
                            )
                            .await?
                            {
                                state = new_state;
                            } else {
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            if msg.contains("end of input") || msg.contains("unexpected EOF") {
                                break;
                            } else {
                                eprintln!("Failed to decode message: {}", e);
                                if !inbox.is_empty() {
                                    inbox.drain(0..1);
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                }
                ReadState::ExpectPayload { size, header } => {
                    if inbox.len() < *size {
                        break;
                    }
                    let payload: Vec<u8> = inbox.drain(0..*size).collect();
                    let hdr = match header.take() {
                        Some(h) => h,
                        None => {
                            eprintln!("Missing header for payload; resetting state");
                            state = ReadState::ExpectHeader;
                            continue;
                        }
                    };

                    handle_payload(
                        hdr,
                        payload,
                        all_events,
                        moose_url,
                        moose_key,
                        session_id,
                        artifact_collector,
                    )
                    .await;

                    state = ReadState::ExpectHeader;
                }
                ReadState::ExpectMemoryDumpPayload { size, header } => {
                    if inbox.len() < *size {
                        break;
                    }
                    let payload: Vec<u8> = inbox.drain(0..*size).collect();
                    let hdr = match header.take() {
                        Some(h) => h,
                        None => {
                            eprintln!("Missing header for memory dump; resetting state");
                            state = ReadState::ExpectHeader;
                            continue;
                        }
                    };

                    handle_memory_dump(hdr, payload, artifact_collector).await;

                    state = ReadState::ExpectHeader;
                }
            }
        }
    }
}

async fn handle_message(
    message: Message,
    all_events: &Vec<Event>,
    moose_url: &str,
    moose_key: &str,
    session_id: &str,
) -> Result<Option<ReadState>> {
    match message {
        Message::EventHeader(header, payload_size) => Ok(Some(ReadState::ExpectPayload {
            size: payload_size as usize,
            header: Some(header),
        })),
        Message::MemoryDump(header, payload_size) => Ok(Some(ReadState::ExpectMemoryDumpPayload {
            size: payload_size as usize,
            header: Some(header),
        })),
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

            send_lifecycle(
                moose_url,
                moose_key,
                session_id,
                "COMPLETED",
                &format!("Tracing finished. Events: {}", all_events.len()),
            )
            .await;

            Ok(None)
        }
    }
}

async fn handle_payload(
    hdr: etw::EventHeader,
    payload: Vec<u8>,
    all_events: &mut Vec<Event>,
    moose_url: &str,
    moose_key: &str,
    session_id: &str,
    artifact_collector: &mut ArtifactCollector,
) {
    let event_type = *hdr.event_type();
    match event_type {
        EtwEvent::SystemProcess(_) => {
            handle_process_event(hdr, payload, all_events, moose_url, moose_key, session_id).await;
        }
        EtwEvent::Sysmon => {
            eprintln!("Sysmon events are not yet supported");
        }
        EtwEvent::File(ref file_event) => {
            handle_file_event(
                hdr,
                payload,
                file_event,
                all_events,
                moose_url,
                moose_key,
                session_id,
                artifact_collector,
            )
            .await;
        }
        EtwEvent::Registry(ref reg_event) => {
            handle_registry_event(
                hdr,
                payload,
                reg_event,
                all_events,
                moose_url,
                moose_key,
                session_id,
                artifact_collector,
            )
            .await;
        }
        EtwEvent::Network(ref net_event) => {
            handle_network_event(
                hdr,
                payload,
                net_event,
                all_events,
                moose_url,
                moose_key,
                session_id,
                artifact_collector,
            )
            .await;
        }
        EtwEvent::Dns(ref dns_event) => {
            handle_dns_event(
                hdr,
                payload,
                dns_event,
                all_events,
                moose_url,
                moose_key,
                session_id,
                artifact_collector,
            )
            .await;
        }
    }
}

async fn handle_process_event(
    hdr: etw::EventHeader,
    payload: Vec<u8>,
    all_events: &mut Vec<Event>,
    moose_url: &str,
    moose_key: &str,
    session_id: &str,
) {
    let process_event = match etw::payload::process::ProcessEventPayload::parse(&payload) {
        Ok(ev) => ev,
        Err(e) => {
            eprintln!("Failed to parse process event payload: {}", e);
            return;
        }
    };

    let action = match hdr.event_type() {
        EtwEvent::SystemProcess(e) => match e {
            etw::ProcessEvent::ProcessCreate => "ProcessCreate",
            etw::ProcessEvent::ProcessTerminate => "ProcessTerminate",
        },
        EtwEvent::Sysmon => "Sysmon",
        _ => "Unknown",
    };

    let severity = {
        let mut rng = rand::thread_rng();
        rng.gen_range(0..100)
    };

    let malware_event = MalwareEvent::new(
        session_id,
        process_event.image().to_string(),
        process_event.pid(),
        process_event.ppid(),
        action,
        Some(process_event.cmd().to_string()),
        Some(process_event.cmd().to_string()),
        severity,
    );

    send_malware_event(moose_url, moose_key, &malware_event).await;

    let event = Event::new(hdr, EventPayload::Process(process_event));
    all_events.push(event);
}

async fn handle_file_event(
    hdr: etw::EventHeader,
    payload: Vec<u8>,
    event_type: &etw::FileEvent,
    all_events: &mut Vec<Event>,
    moose_url: &str,
    moose_key: &str,
    session_id: &str,
    artifact_collector: &mut ArtifactCollector,
) {
    if let etw::FileEvent::Create = event_type {
        if let Ok(payload) = etw::payload::file::FileCreatePayload::parse(&payload) {
            let severity = {
                let mut rng = rand::thread_rng();
                rng.gen_range(0..50)
            };
            let malware_event = MalwareEvent::new(
                session_id,
                format!("PID:{}", hdr.pid()),
                hdr.pid(),
                0,
                "FileCreate",
                Some(payload.open_path.clone()),
                None,
                severity,
            );
            send_malware_event(moose_url, moose_key, &malware_event).await;

            artifact_collector.track_file_create(&payload.open_path, Some(hdr.pid()));

            let event = Event::new(hdr, EventPayload::File(payload));
            all_events.push(event);
        }
    }
}

async fn handle_registry_event(
    hdr: etw::EventHeader,
    payload: Vec<u8>,
    event_type: &etw::RegistryEvent,
    all_events: &mut Vec<Event>,
    moose_url: &str,
    moose_key: &str,
    session_id: &str,
    artifact_collector: &mut ArtifactCollector,
) {
    if let etw::RegistryEvent::SetValue = event_type {
        if let Ok(payload) = etw::payload::registry::RegistryEventPayload::parse(&payload) {
            let malware_event = MalwareEvent::new(
                session_id,
                format!("PID:{}", hdr.pid()),
                hdr.pid(),
                0,
                "RegistrySetValue",
                Some(payload.key_name.clone()),
                None,
                50,
            );
            send_malware_event(moose_url, moose_key, &malware_event).await;

            artifact_collector.track_registry_change(
                &payload.key_name,
                None,
                None,
                "SetValue",
                Some(hdr.pid()),
            );

            let event = Event::new(hdr, EventPayload::Registry(payload));
            all_events.push(event);
        }
    }
}

async fn handle_network_event(
    hdr: etw::EventHeader,
    payload: Vec<u8>,
    event_type: &etw::NetworkEvent,
    all_events: &mut Vec<Event>,
    moose_url: &str,
    moose_key: &str,
    session_id: &str,
    artifact_collector: &mut ArtifactCollector,
) {
    let etw::NetworkEvent::Connect = event_type;
    if let Ok(payload) = etw::payload::network::NetworkEventPayload::parse(&payload) {
        let malware_event = MalwareEvent::new(
            session_id,
            format!("PID:{}", hdr.pid()),
            hdr.pid(),
            0,
            "TcpIpConnect",
            Some(format!("{}:{}", payload.dest_ip, payload.dest_port)),
            Some(format!("{}:{}", payload.src_ip, payload.src_port)),
            50,
        );
        send_malware_event(moose_url, moose_key, &malware_event).await;

        artifact_collector.track_network_ioc(
            "ip",
            &format!("{}:{}", payload.dest_ip, payload.dest_port),
            "tcp",
            Some(payload.dest_port),
            Some(hdr.pid()),
        );

        let event = Event::new(hdr, EventPayload::Network(payload));
        all_events.push(event);
    }
}

async fn handle_dns_event(
    hdr: etw::EventHeader,
    payload: Vec<u8>,
    event_type: &etw::DnsEvent,
    all_events: &mut Vec<Event>,
    moose_url: &str,
    moose_key: &str,
    session_id: &str,
    artifact_collector: &mut ArtifactCollector,
) {
    let etw::DnsEvent::Query = event_type;
    if let Ok(payload) = etw::payload::dns::DnsEventPayload::parse(&payload) {
        let malware_event = MalwareEvent::new(
            session_id,
            format!("PID:{}", hdr.pid()),
            hdr.pid(),
            0,
            "DnsQuery",
            Some(payload.query_name.clone()),
            Some(format!("Type: {}", payload.query_type)),
            20,
        );
        send_malware_event(moose_url, moose_key, &malware_event).await;

        artifact_collector.track_network_ioc(
            "domain",
            &payload.query_name,
            "dns",
            None,
            Some(hdr.pid()),
        );

        let event = Event::new(hdr, EventPayload::Dns(payload));
        all_events.push(event);
    }
}

async fn handle_memory_dump(
    hdr: MemoryDumpHeader,
    payload: Vec<u8>,
    artifact_collector: &mut ArtifactCollector,
) {
    println!(
        "Received memory dump ({} bytes) from PID {} Trigger: {}",
        payload.len(),
        hdr.pid,
        hdr.trigger
    );

    if let Err(e) = artifact_collector
        .save_memory_dump(
            hdr.pid,
            &hdr.process_name,
            hdr.region_base,
            &hdr.protection,
            &hdr.trigger,
            &payload,
        )
        .await
    {
        eprintln!("Failed to save memory dump: {}", e);
    }
}
