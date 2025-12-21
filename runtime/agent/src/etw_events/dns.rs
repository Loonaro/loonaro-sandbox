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
use std::rc::Rc;
use tokio::sync::mpsc;

// dns query type mapping
fn query_type_to_string(qtype: u16) -> String {
    match qtype {
        1 => "A".to_string(),
        2 => "NS".to_string(),
        5 => "CNAME".to_string(),
        6 => "SOA".to_string(),
        12 => "PTR".to_string(),
        15 => "MX".to_string(),
        16 => "TXT".to_string(),
        28 => "AAAA".to_string(),
        33 => "SRV".to_string(),
        255 => "ANY".to_string(),
        _ => format!("TYPE{}", qtype),
    }
}

// dns response code mapping
fn rcode_to_string(rcode: u32) -> String {
    match rcode {
        0 => "NOERROR".to_string(),
        1 => "FORMERR".to_string(),
        2 => "SERVFAIL".to_string(),
        3 => "NXDOMAIN".to_string(),
        4 => "NOTIMP".to_string(),
        5 => "REFUSED".to_string(),
        _ => format!("RCODE{}", rcode),
    }
}

pub fn register_dns_client(
    etw: &mut EtwSession,
    tx: mpsc::Sender<AgentMessage>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // Microsoft-Windows-DNS-Client {1c95126e-7eea-49a9-a3fe-a378b03ddb4d}
    let guid = Guid::from_u128(0x1c95126e_7eea_49a9_a3fe_a378b03ddb4d);
    etw.enable_provider(guid);

    // event 3019: dns query started
    let mut event = Event::new(3019, "Dns::QueryStart".into());
    *event.extension_mut().provider_mut() = guid;

    let ancillary_clone = ancillary.clone();
    let tx_clone = tx.clone();
    let counter_clone = counter.clone();

    event.add_callback(move |data: &EventData| -> Result<()> {
        *counter_clone.borrow_mut() += 1;

        let payload = data.event_data();
        if let Ok(ev) = parse_dns_query_event(&payload) {
            let mut timestamp = 0;
            ancillary_clone.read(|a| timestamp = a.time());

            let msg = AgentMessage {
                payload: Some(agent_message::Payload::Event(MalwareEvent {
                    session_id: String::new(),
                    timestamp: filetime_to_rfc3339(timestamp),
                    severity: 0,
                    category: SigmaCategory::CategoryDnsQuery.into(),
                    event: Some(loonaro_models::sigma::malware_event::Event::Network(ev)),
                })),
            };
            let _ = tx_clone.try_send(msg);
        }
        Ok(())
    });

    etw.add_event(event, None);

    // event 3020: dns query completed (has response)
    let mut response_event = Event::new(3020, "Dns::QueryComplete".into());
    *response_event.extension_mut().provider_mut() = guid;

    let ancillary_resp = ancillary.clone();
    let tx_resp = tx.clone();
    let counter_resp = counter.clone();

    response_event.add_callback(move |data: &EventData| -> Result<()> {
        *counter_resp.borrow_mut() += 1;

        let payload = data.event_data();
        if let Ok(ev) = parse_dns_response_event(&payload) {
            let mut timestamp = 0;
            ancillary_resp.read(|a| timestamp = a.time());

            let msg = AgentMessage {
                payload: Some(agent_message::Payload::Event(MalwareEvent {
                    session_id: String::new(),
                    timestamp: filetime_to_rfc3339(timestamp),
                    severity: 0,
                    category: SigmaCategory::CategoryDnsQuery.into(),
                    event: Some(loonaro_models::sigma::malware_event::Event::Network(ev)),
                })),
            };
            let _ = tx_resp.try_send(msg);
        }
        Ok(())
    });

    etw.add_event(response_event, None);
}

// dns query event 3019 layout:
// queryname (utf16-z)
// querytype (u16)
// queryoptions (u32)
fn parse_dns_query_event(data: &[u8]) -> Result<NetworkEvent, utils::ParseError> {
    let (query_name, rest) = utils::take_utf16le_z(data)?;

    let query_type = if rest.len() >= 2 {
        u16::from_le_bytes([rest[0], rest[1]])
    } else {
        0
    };

    let query_options = if rest.len() >= 6 {
        u32::from_le_bytes([rest[2], rest[3], rest[4], rest[5]])
    } else {
        0
    };

    Ok(NetworkEvent {
        protocol: "DNS".to_string(),
        source_ip: String::new(),
        source_port: 0,
        destination_ip: String::new(),
        destination_port: 53,
        image: String::new(),
        user: String::new(),
        query_name,
        network_connection_state: "query".to_string(),
        source_packets: 0,
        destination_packets: 0,
        source_bytes: 0,
        destination_bytes: 0,
        community_id: String::new(),
        dns_id: format!("{:08x}", query_options),
        dns_question_type: query_type_to_string(query_type),
        dns_answers_data: String::new(),
        dns_response_code: String::new(),
    })
}

// dns response event 3020 layout:
// queryname (utf16-z)
// querytype (u16)
// queryoptions (u32)
// querystatus (u32)
// queryresults (utf16-z) - space separated IPs or "no records"
fn parse_dns_response_event(data: &[u8]) -> Result<NetworkEvent, utils::ParseError> {
    let (query_name, rest) = utils::take_utf16le_z(data)?;

    let query_type = if rest.len() >= 2 {
        u16::from_le_bytes([rest[0], rest[1]])
    } else {
        0
    };

    let query_options = if rest.len() >= 6 {
        u32::from_le_bytes([rest[2], rest[3], rest[4], rest[5]])
    } else {
        0
    };

    let query_status = if rest.len() >= 10 {
        u32::from_le_bytes([rest[6], rest[7], rest[8], rest[9]])
    } else {
        0
    };

    let answers = if rest.len() > 10 {
        utils::take_utf16le_z(&rest[10..])
            .map(|(s, _)| s)
            .unwrap_or_default()
    } else {
        String::new()
    };

    Ok(NetworkEvent {
        protocol: "DNS".to_string(),
        source_ip: String::new(),
        source_port: 0,
        destination_ip: String::new(),
        destination_port: 53,
        image: String::new(),
        user: String::new(),
        query_name,
        network_connection_state: "response".to_string(),
        source_packets: 0,
        destination_packets: 0,
        source_bytes: 0,
        destination_bytes: 0,
        community_id: String::new(),
        dns_id: format!("{:08x}", query_options),
        dns_question_type: query_type_to_string(query_type),
        dns_answers_data: answers,
        dns_response_code: rcode_to_string(query_status),
    })
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
