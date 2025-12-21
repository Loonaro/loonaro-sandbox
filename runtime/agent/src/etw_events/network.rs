use crate::utils;
use anyhow::Result;
use loonaro_models::sigma::{
    agent_message, AgentMessage, MalwareEvent, NetworkEvent, SigmaCategory,
};
use one_collect::etw::{AncillaryData, EtwSession};
use one_collect::event::{Event, EventData};
use one_collect::Guid;
use one_collect::ReadOnly;
use std::cell::RefCell;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::rc::Rc;
use tokio::sync::mpsc;

pub fn register_network(
    etw: &mut EtwSession,
    tx: mpsc::Sender<AgentMessage>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // Microsoft-Windows-TCPIP {2f07e2ee-15db-40f1-90ef-9d7ba282188a}
    let guid = Guid::from_u128(0x2f07e2ee_15db_40f1_90ef_9d7ba282188a);
    etw.enable_provider(guid);

    // tcp ipv4 events
    let tcp_v4_events = vec![
        (12, "TcpConnect", "outbound"), // tcp connect ipv4
        (15, "TcpDisconnect", "close"), // tcp disconnect
        (28, "TcpAccept", "inbound"),   // tcp accept (server)
    ];

    for (opcode, name, state) in tcp_v4_events {
        let mut event = Event::new(opcode, format!("TcpIp::{}", name));
        *event.extension_mut().provider_mut() = guid;

        let ancillary_clone = ancillary.clone();
        let tx_clone = tx.clone();
        let counter_clone = counter.clone();
        let state_str = state.to_string();

        event.add_callback(move |data: &EventData| -> Result<()> {
            *counter_clone.borrow_mut() += 1;

            let payload = data.event_data();
            if let Ok(ev) = parse_tcp_v4_event(&payload, &state_str) {
                let mut timestamp = 0;
                ancillary_clone.read(|a| timestamp = a.time());

                let msg = AgentMessage {
                    payload: Some(agent_message::Payload::Event(MalwareEvent {
                        session_id: String::new(),
                        timestamp: filetime_to_rfc3339(timestamp),
                        severity: 0,
                        category: SigmaCategory::CategoryNetworkConnection.into(),
                        event: Some(loonaro_models::sigma::malware_event::Event::Network(ev)),
                    })),
                };
                let _ = tx_clone.try_send(msg);
            }
            Ok(())
        });

        etw.add_event(event, None);
    }

    // tcp ipv6 events
    let tcp_v6_events = vec![
        (16, "TcpConnectV6", "outbound"),
        (19, "TcpDisconnectV6", "close"),
        (31, "TcpAcceptV6", "inbound"),
    ];

    for (opcode, name, state) in tcp_v6_events {
        let mut event = Event::new(opcode, format!("TcpIp::{}", name));
        *event.extension_mut().provider_mut() = guid;

        let ancillary_clone = ancillary.clone();
        let tx_clone = tx.clone();
        let counter_clone = counter.clone();
        let state_str = state.to_string();

        event.add_callback(move |data: &EventData| -> Result<()> {
            *counter_clone.borrow_mut() += 1;

            let payload = data.event_data();
            if let Ok(ev) = parse_tcp_v6_event(&payload, &state_str) {
                let mut timestamp = 0;
                ancillary_clone.read(|a| timestamp = a.time());

                let msg = AgentMessage {
                    payload: Some(agent_message::Payload::Event(MalwareEvent {
                        session_id: String::new(),
                        timestamp: filetime_to_rfc3339(timestamp),
                        severity: 0,
                        category: SigmaCategory::CategoryNetworkConnection.into(),
                        event: Some(loonaro_models::sigma::malware_event::Event::Network(ev)),
                    })),
                };
                let _ = tx_clone.try_send(msg);
            }
            Ok(())
        });

        etw.add_event(event, None);
    }

    // udp ipv4 events
    let udp_v4_events = vec![(17, "UdpSend", "outbound"), (18, "UdpReceive", "inbound")];

    for (opcode, name, state) in udp_v4_events {
        let mut event = Event::new(opcode, format!("UdpIp::{}", name));
        *event.extension_mut().provider_mut() = guid;

        let ancillary_clone = ancillary.clone();
        let tx_clone = tx.clone();
        let counter_clone = counter.clone();
        let state_str = state.to_string();

        event.add_callback(move |data: &EventData| -> Result<()> {
            *counter_clone.borrow_mut() += 1;

            let payload = data.event_data();
            if let Ok(ev) = parse_udp_v4_event(&payload, &state_str) {
                let mut timestamp = 0;
                ancillary_clone.read(|a| timestamp = a.time());

                let msg = AgentMessage {
                    payload: Some(agent_message::Payload::Event(MalwareEvent {
                        session_id: String::new(),
                        timestamp: filetime_to_rfc3339(timestamp),
                        severity: 0,
                        category: SigmaCategory::CategoryNetworkConnection.into(),
                        event: Some(loonaro_models::sigma::malware_event::Event::Network(ev)),
                    })),
                };
                let _ = tx_clone.try_send(msg);
            }
            Ok(())
        });

        etw.add_event(event, None);
    }
}

// tcp connect/disconnect ipv4 layout (typical):
// offset 0: pid (u32)
// offset 4: size (u32)
// offset 8: local addr (4 bytes)
// offset 12: remote addr (4 bytes)
// offset 16: local port (u16 big-endian)
// offset 18: remote port (u16 big-endian)
fn parse_tcp_v4_event(data: &[u8], state: &str) -> Result<NetworkEvent, utils::ParseError> {
    if data.len() < 20 {
        return Err(utils::ParseError::Bounds);
    }

    let pid = utils::read_u32(data, 0)?;
    let local_addr = Ipv4Addr::new(data[8], data[9], data[10], data[11]);
    let remote_addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    // ports are big-endian in network events
    let local_port = u16::from_be_bytes([data[16], data[17]]);
    let remote_port = u16::from_be_bytes([data[18], data[19]]);

    Ok(NetworkEvent {
        protocol: "TCP".to_string(),
        source_ip: local_addr.to_string(),
        source_port: local_port as u32,
        destination_ip: remote_addr.to_string(),
        destination_port: remote_port as u32,
        image: get_process_image(pid),
        user: String::new(),
        query_name: String::new(),
        network_connection_state: state.to_string(),
        source_packets: 0,
        destination_packets: 0,
        source_bytes: 0,
        destination_bytes: 0,
        community_id: generate_community_id(
            "TCP",
            &local_addr.to_string(),
            local_port,
            &remote_addr.to_string(),
            remote_port,
        ),
        dns_id: String::new(),
        dns_question_type: String::new(),
        dns_answers_data: String::new(),
        dns_response_code: String::new(),
    })
}

// tcp ipv6 layout:
// offset 0: pid (u32)
// offset 4: size (u32)
// offset 8: local addr (16 bytes)
// offset 24: remote addr (16 bytes)
// offset 40: local port (u16 big-endian)
// offset 42: remote port (u16 big-endian)
fn parse_tcp_v6_event(data: &[u8], state: &str) -> Result<NetworkEvent, utils::ParseError> {
    if data.len() < 44 {
        return Err(utils::ParseError::Bounds);
    }

    let pid = utils::read_u32(data, 0)?;

    let local_addr = Ipv6Addr::new(
        u16::from_be_bytes([data[8], data[9]]),
        u16::from_be_bytes([data[10], data[11]]),
        u16::from_be_bytes([data[12], data[13]]),
        u16::from_be_bytes([data[14], data[15]]),
        u16::from_be_bytes([data[16], data[17]]),
        u16::from_be_bytes([data[18], data[19]]),
        u16::from_be_bytes([data[20], data[21]]),
        u16::from_be_bytes([data[22], data[23]]),
    );

    let remote_addr = Ipv6Addr::new(
        u16::from_be_bytes([data[24], data[25]]),
        u16::from_be_bytes([data[26], data[27]]),
        u16::from_be_bytes([data[28], data[29]]),
        u16::from_be_bytes([data[30], data[31]]),
        u16::from_be_bytes([data[32], data[33]]),
        u16::from_be_bytes([data[34], data[35]]),
        u16::from_be_bytes([data[36], data[37]]),
        u16::from_be_bytes([data[38], data[39]]),
    );

    let local_port = u16::from_be_bytes([data[40], data[41]]);
    let remote_port = u16::from_be_bytes([data[42], data[43]]);

    Ok(NetworkEvent {
        protocol: "TCP".to_string(),
        source_ip: local_addr.to_string(),
        source_port: local_port as u32,
        destination_ip: remote_addr.to_string(),
        destination_port: remote_port as u32,
        image: get_process_image(pid),
        user: String::new(),
        query_name: String::new(),
        network_connection_state: state.to_string(),
        source_packets: 0,
        destination_packets: 0,
        source_bytes: 0,
        destination_bytes: 0,
        community_id: generate_community_id(
            "TCP",
            &local_addr.to_string(),
            local_port,
            &remote_addr.to_string(),
            remote_port,
        ),
        dns_id: String::new(),
        dns_question_type: String::new(),
        dns_answers_data: String::new(),
        dns_response_code: String::new(),
    })
}

// udp send/receive ipv4 layout similar to tcp
fn parse_udp_v4_event(data: &[u8], state: &str) -> Result<NetworkEvent, utils::ParseError> {
    if data.len() < 20 {
        return Err(utils::ParseError::Bounds);
    }

    let pid = utils::read_u32(data, 0)?;
    let local_addr = Ipv4Addr::new(data[8], data[9], data[10], data[11]);
    let remote_addr = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let local_port = u16::from_be_bytes([data[16], data[17]]);
    let remote_port = u16::from_be_bytes([data[18], data[19]]);

    Ok(NetworkEvent {
        protocol: "UDP".to_string(),
        source_ip: local_addr.to_string(),
        source_port: local_port as u32,
        destination_ip: remote_addr.to_string(),
        destination_port: remote_port as u32,
        image: get_process_image(pid),
        user: String::new(),
        query_name: String::new(),
        network_connection_state: state.to_string(),
        source_packets: 0,
        destination_packets: 0,
        source_bytes: 0,
        destination_bytes: 0,
        community_id: generate_community_id(
            "UDP",
            &local_addr.to_string(),
            local_port,
            &remote_addr.to_string(),
            remote_port,
        ),
        dns_id: String::new(),
        dns_question_type: String::new(),
        dns_answers_data: String::new(),
        dns_response_code: String::new(),
    })
}

// get process image path from pid using windows api
fn get_process_image(pid: u32) -> String {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetProcessImageFileNameW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if let Ok(h) = handle {
                if !h.is_invalid() {
                    let mut buffer = [0u16; 260];
                    let len = GetProcessImageFileNameW(h, &mut buffer);
                    let _ = CloseHandle(h);
                    if len > 0 {
                        return String::from_utf16_lossy(&buffer[..len as usize]);
                    }
                }
            }
        }
    }
    String::new()
}

// community id is a standard network flow hash (simplified version)
fn generate_community_id(
    proto: &str,
    src_ip: &str,
    src_port: u16,
    dst_ip: &str,
    dst_port: u16,
) -> String {
    use sha1::{Digest, Sha1};

    // simplified: just hash the tuple
    let proto_num = match proto {
        "TCP" => 6u8,
        "UDP" => 17u8,
        _ => 0u8,
    };

    // ensure consistent ordering (lower ip first for bidirectional flows)
    let (a_ip, a_port, b_ip, b_port) =
        if src_ip < dst_ip || (src_ip == dst_ip && src_port < dst_port) {
            (src_ip, src_port, dst_ip, dst_port)
        } else {
            (dst_ip, dst_port, src_ip, src_port)
        };

    let seed: u16 = 0; // community id seed
    let mut hasher = Sha1::new();
    hasher.update(seed.to_be_bytes());
    hasher.update(a_ip.as_bytes());
    hasher.update(b_ip.as_bytes());
    hasher.update(&[proto_num]);
    hasher.update(a_port.to_be_bytes());
    hasher.update(b_port.to_be_bytes());

    let result = hasher.finalize();
    format!(
        "1:{}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &result[..])
    )
}

fn filetime_to_rfc3339(filetime: u64) -> String {
    let intervals = filetime;
    let seconds = intervals / 10_000_000;
    let nanos = (intervals % 10_000_000) * 100;
    let unix_seconds = (seconds as i64) - 11_644_473_600;
    match chrono::DateTime::from_timestamp(unix_seconds, nanos as u32) {
        Some(dt) => dt.to_rfc3339(),
        None => "1970-01-01T00:00:00Z".to_string(),
    }
}
