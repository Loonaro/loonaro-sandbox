//! handle duplication events for token theft and privilege escalation detection
//! catches handle abuse techniques used by malware

use crate::cache;
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

pub fn register_handle_events(
    etw: &mut EtwSession,
    tx: mpsc::Sender<AgentMessage>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // Microsoft-Windows-Kernel-Audit-API-Calls {E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}
    let guid = Guid::from_u128(0xE02A841C_75A3_4FA7_AFC8_AE09CF9B7F23);
    etw.enable_provider(guid);

    // handle operations
    let events = vec![
        (1, "OpenProcess"),     // privilege escalation
        (2, "OpenThread"),      // thread manipulation
        (3, "DuplicateHandle"), // token theft
    ];

    for (opcode, name) in events {
        let mut event = Event::new(opcode, format!("Handle::{}", name));
        *event.extension_mut().provider_mut() = guid;

        let tx_clone = tx.clone();
        let ancillary_clone = ancillary.clone();
        let counter_clone = counter.clone();

        event.add_callback(move |data: &EventData| -> Result<()> {
            *counter_clone.borrow_mut() += 1;

            let payload = data.event_data();
            if let Ok(handle_event) = parse_handle_event(&payload, opcode as u16) {
                // skip same-process operations
                if handle_event.process_id != handle_event.parent_process_id {
                    let mut timestamp = 0;
                    ancillary_clone.read(|a| timestamp = a.time());

                    let severity: u32 = match opcode {
                        3 => 70, // duplicate handle (token theft)
                        1 => 50, // open process
                        _ => 30,
                    };

                    let msg = AgentMessage {
                        payload: Some(agent_message::Payload::Event(MalwareEvent {
                            session_id: String::new(),
                            timestamp: utils::filetime_to_rfc3339(timestamp),
                            severity,
                            category: SigmaCategory::CategoryProcessAccess.into(),
                            event: Some(loonaro_models::sigma::malware_event::Event::Process(
                                handle_event,
                            )),
                        })),
                    };
                    let _ = tx_clone.try_send(msg);
                }
            }
            Ok(())
        });

        etw.add_event(event, None);
    }
}

fn parse_handle_event(data: &[u8], _opcode: u16) -> Result<ProcessEvent, utils::ParseError> {
    if data.len() < 16 {
        return Err(utils::ParseError::Bounds);
    }

    // layout: source pid, target pid, desired access, handle
    let source_pid = utils::read_u32(data, 0)?;
    let target_pid = utils::read_u32(data, 4)?;
    let desired_access = utils::read_u32(data, 8)?;

    let (source_image, source_user) = cache::get_cache()
        .get_process_info(source_pid)
        .map(|p| (p.image, p.user))
        .unwrap_or_default();

    let target_image = cache::get_cache()
        .get_process_info(target_pid)
        .map(|p| p.image)
        .unwrap_or_default();

    Ok(ProcessEvent {
        utc_time: String::new(),
        process_guid: String::new(),
        process_id: target_pid,
        image: target_image,
        file_version: String::new(),
        description: format!("Access mask: 0x{:08X}", desired_access),
        product: String::new(),
        company: String::new(),
        command_line: String::new(),
        current_directory: String::new(),
        user: source_user,
        logon_guid: String::new(),
        logon_id: String::new(),
        terminal_session_id: 0,
        integrity_level: String::new(),
        md5: String::new(),
        sha1: String::new(),
        sha256: String::new(),
        imphash: String::new(),
        parent_process_guid: String::new(),
        parent_process_id: source_pid,
        parent_image: source_image,
        parent_command_line: String::new(),
    })
}
