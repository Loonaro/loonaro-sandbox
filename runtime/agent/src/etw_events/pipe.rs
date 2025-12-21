//! named pipe events for c2 and lateral movement detection
//! detects cobaltstrike, emotet, and other pipe-based malware

use crate::cache;
use crate::utils;
use anyhow::Result;
use loonaro_models::sigma::{agent_message, AgentMessage, FileEvent, MalwareEvent, SigmaCategory};
use one_collect::etw::{AncillaryData, EtwSession};
use one_collect::event::{Event, EventData};
use one_collect::Guid;
use one_collect::ReadOnly;
use std::cell::RefCell;
use std::rc::Rc;
use tokio::sync::mpsc;

const OFF_TTID: usize = 16;
const OFF_FILENAME: usize = 28;

pub fn register_pipe_events(
    etw: &mut EtwSession,
    tx: mpsc::Sender<AgentMessage>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // Microsoft-Windows-Kernel-File {EDD08927-9CC4-4E65-B970-C2560FB5C289}
    let guid = Guid::from_u128(0xEDD08927_9CC4_4E65_B970_C2560FB5C289);
    etw.enable_provider(guid);

    let events = vec![
        (30, "NamedPipeCreate", SigmaCategory::CategoryPipeCreated),
        (31, "NamedPipeConnect", SigmaCategory::CategoryPipeCreated),
    ];

    for (opcode, name, category) in events {
        let mut event = Event::new(opcode, format!("Pipe::{}", name));
        *event.extension_mut().provider_mut() = guid;

        let tx_clone = tx.clone();
        let ancillary_clone = ancillary.clone();
        let counter_clone = counter.clone();

        event.add_callback(move |data: &EventData| -> Result<()> {
            *counter_clone.borrow_mut() += 1;

            let payload = data.event_data();
            if let Ok(pipe_event) = parse_pipe_event(&payload) {
                if should_report_pipe(&pipe_event.target_filename) {
                    let mut timestamp = 0;
                    ancillary_clone.read(|a| timestamp = a.time());

                    let msg = AgentMessage {
                        payload: Some(agent_message::Payload::Event(MalwareEvent {
                            session_id: String::new(),
                            timestamp: utils::filetime_to_rfc3339(timestamp),
                            severity: calculate_pipe_severity(&pipe_event.target_filename) as u32,
                            category: category.into(),
                            event: Some(loonaro_models::sigma::malware_event::Event::File(
                                pipe_event,
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

fn parse_pipe_event(data: &[u8]) -> Result<FileEvent, utils::ParseError> {
    if data.len() < OFF_FILENAME {
        return Err(utils::ParseError::Bounds);
    }

    let tid = utils::read_u32(data, OFF_TTID).unwrap_or(0);
    let pid = utils::get_pid_from_tid(tid);

    let filename_data = data.get(OFF_FILENAME..).ok_or(utils::ParseError::Bounds)?;
    let (pipe_name, _) = utils::take_utf16le_z(filename_data)?;

    let (image, user) = cache::get_cache()
        .get_process_info(pid)
        .map(|p| (p.image, p.user))
        .unwrap_or_default();

    Ok(FileEvent {
        target_filename: pipe_name,
        image,
        action: String::new(),
        sha256: String::new(),
        user,
        utc_time: String::new(),
        process_guid: String::new(),
        process_id: pid,
        creation_utc_time: String::new(),
    })
}

fn should_report_pipe(name: &str) -> bool {
    let lower = name.to_lowercase();

    let suspicious = [
        "cobaltstrike",
        "msagent_",
        "postex_",
        "status_",
        "msse-",
        "msadcs_",
        "dce-",
        "spooler_",
        "ntds_",
        "scerpc_",
        "mspipe-",
        "beacon",
        "puppet",
        "meow",
        "kittens",
        "lsass",
        "msfpipe",
    ];

    for pattern in &suspicious {
        if lower.contains(pattern) {
            return true;
        }
    }

    if lower.starts_with("\\\\pipe\\") {
        let pipe_part = &lower[7..];
        if pipe_part.len() > 20 && pipe_part.chars().filter(|c| c.is_ascii_hexdigit()).count() > 15
        {
            return true;
        }
    }

    let system_pipes = [
        "\\\\pipe\\lsarpc",
        "\\\\pipe\\samr",
        "\\\\pipe\\netlogon",
        "\\\\pipe\\svcctl",
        "\\\\pipe\\browser",
        "\\\\pipe\\wkssvc",
        "\\\\pipe\\srvsvc",
        "\\\\pipe\\eventlog",
        "\\\\pipe\\ntsvcs",
    ];

    for sys in &system_pipes {
        if lower == *sys {
            return false;
        }
    }

    true
}

fn calculate_pipe_severity(name: &str) -> i32 {
    let lower = name.to_lowercase();

    if lower.contains("cobaltstrike") || lower.contains("beacon") || lower.contains("msfpipe") {
        return 90;
    }

    if lower.contains("msagent_") || lower.contains("postex_") {
        return 70;
    }

    if lower.len() > 30 {
        return 50;
    }

    20
}
