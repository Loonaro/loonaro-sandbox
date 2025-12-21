//! wmi activity events for persistence and execution detection
//! catches script-based malware using wmi for execution or persistence

use crate::utils;
use anyhow::Result;
use loonaro_models::sigma::{
    agent_message, AgentMessage, MalwareEvent, ProcessEvent, SigmaCategory,
};
use one_collect::etw::{AncillaryData, EtwSession};
use one_collect::event::{Event, EventData};
use one_collect::Guid;
use one_collect::ReadOnly;
use std::cell::RefCell;
use std::rc::Rc;
use tokio::sync::mpsc;

pub fn register_wmi_events(
    etw: &mut EtwSession,
    tx: mpsc::Sender<AgentMessage>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // Microsoft-Windows-WMI-Activity {1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}
    let guid = Guid::from_u128(0x1418EF04_B0B4_4623_BF7E_D74AB47BBDAA);
    etw.enable_provider(guid);

    // wmi operation events
    let events = vec![
        (11, "ProviderLoad"),   // wmi provider loaded
        (12, "TemporaryEvent"), // temporary event subscription (persistence)
        (13, "PermanentEvent"), // permanent event subscription (persistence)
        (22, "ExecMethod"),     // method execution
        (23, "ExecQuery"),      // query execution
    ];

    for (opcode, name) in events {
        let mut event = Event::new(opcode, format!("WMI::{}", name));
        *event.extension_mut().provider_mut() = guid;

        let tx_clone = tx.clone();
        let ancillary_clone = ancillary.clone();
        let counter_clone = counter.clone();

        event.add_callback(move |data: &EventData| -> Result<()> {
            *counter_clone.borrow_mut() += 1;

            let payload = data.event_data();
            if let Ok(wmi_event) = parse_wmi_event(&payload, opcode as u16) {
                let mut timestamp = 0;
                ancillary_clone.read(|a| timestamp = a.time());

                let severity: u32 = match opcode {
                    12 | 13 => 70, // event subscriptions (persistence)
                    22 => 50,      // method execution
                    _ => 20,
                };

                let msg = AgentMessage {
                    payload: Some(agent_message::Payload::Event(MalwareEvent {
                        session_id: String::new(),
                        timestamp: utils::filetime_to_rfc3339(timestamp),
                        severity,
                        category: SigmaCategory::CategoryWmiEvent.into(),
                        event: Some(loonaro_models::sigma::malware_event::Event::Process(
                            wmi_event,
                        )),
                    })),
                };
                let _ = tx_clone.try_send(msg);
            }
            Ok(())
        });

        etw.add_event(event, None);
    }
}

fn parse_wmi_event(data: &[u8], opcode: u16) -> Result<ProcessEvent, utils::ParseError> {
    // wmi events have variable format, extract what we can
    let (operation, namespace, query) = extract_wmi_strings(data);

    Ok(ProcessEvent {
        utc_time: String::new(),
        process_guid: String::new(),
        process_id: 0,
        image: "WMI".to_string(),
        file_version: String::new(),
        description: format!("Op={} Query={}", opcode, query),
        product: String::new(),
        company: String::new(),
        command_line: query,
        current_directory: namespace,
        user: String::new(),
        logon_guid: String::new(),
        logon_id: String::new(),
        terminal_session_id: 0,
        integrity_level: String::new(),
        md5: String::new(),
        sha1: String::new(),
        sha256: String::new(),
        imphash: String::new(),
        parent_process_guid: String::new(),
        parent_process_id: 0,
        parent_image: operation,
        parent_command_line: String::new(),
    })
}

fn extract_wmi_strings(data: &[u8]) -> (String, String, String) {
    // try to extract utf-16 strings from wmi event data
    let mut strings = Vec::new();
    let mut pos = 0;

    while pos < data.len() && strings.len() < 3 {
        if let Ok((s, rest)) = utils::take_utf16le_z(&data[pos..]) {
            if !s.is_empty() {
                strings.push(s);
            }
            let consumed = data.len() - pos - rest.len();
            pos += consumed.max(2);
        } else {
            pos += 2;
        }
    }

    (
        strings.get(0).cloned().unwrap_or_default(),
        strings.get(1).cloned().unwrap_or_default(),
        strings.get(2).cloned().unwrap_or_default(),
    )
}
