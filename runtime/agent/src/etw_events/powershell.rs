//! powershell script block logging for fileless malware detection
//! captures executed script content for analysis

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

pub fn register_powershell_events(
    etw: &mut EtwSession,
    tx: mpsc::Sender<AgentMessage>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // Microsoft-Windows-PowerShell {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
    let guid = Guid::from_u128(0xA0C1853B_5C40_4B15_8766_3CF1C58F985A);
    etw.enable_provider(guid);

    // event 4104: script block logging
    let mut event = Event::new(4104, "PowerShell::ScriptBlock".into());
    *event.extension_mut().provider_mut() = guid;

    let tx_clone = tx.clone();
    let ancillary_clone = ancillary.clone();
    let counter_clone = counter.clone();

    event.add_callback(move |data: &EventData| -> Result<()> {
        *counter_clone.borrow_mut() += 1;

        let payload = data.event_data();
        if let Ok(ps_event) = parse_powershell_event(&payload) {
            let mut timestamp = 0;
            ancillary_clone.read(|a| timestamp = a.time());

            let severity = calculate_script_severity(&ps_event.command_line);

            let msg = AgentMessage {
                payload: Some(agent_message::Payload::Event(MalwareEvent {
                    session_id: String::new(),
                    timestamp: utils::filetime_to_rfc3339(timestamp),
                    severity: severity as u32,
                    category: SigmaCategory::CategoryProcessCreation.into(),
                    event: Some(loonaro_models::sigma::malware_event::Event::Process(
                        ps_event,
                    )),
                })),
            };
            let _ = tx_clone.try_send(msg);
        }
        Ok(())
    });

    etw.add_event(event, None);

    // event 4103: module logging
    let mut module_event = Event::new(4103, "PowerShell::ModuleLoad".into());
    *module_event.extension_mut().provider_mut() = guid;

    let tx_mod = tx.clone();
    let ancillary_mod = ancillary.clone();
    let counter_mod = counter.clone();

    module_event.add_callback(move |data: &EventData| -> Result<()> {
        *counter_mod.borrow_mut() += 1;

        let payload = data.event_data();
        if let Ok(ps_event) = parse_powershell_event(&payload) {
            let mut timestamp = 0;
            ancillary_mod.read(|a| timestamp = a.time());

            let msg = AgentMessage {
                payload: Some(agent_message::Payload::Event(MalwareEvent {
                    session_id: String::new(),
                    timestamp: utils::filetime_to_rfc3339(timestamp),
                    severity: 20,
                    category: SigmaCategory::CategoryProcessCreation.into(),
                    event: Some(loonaro_models::sigma::malware_event::Event::Process(
                        ps_event,
                    )),
                })),
            };
            let _ = tx_mod.try_send(msg);
        }
        Ok(())
    });

    etw.add_event(module_event, None);
}

fn parse_powershell_event(data: &[u8]) -> Result<ProcessEvent, utils::ParseError> {
    // script block events contain script text as utf-16
    let script_content = if let Ok((s, _)) = utils::take_utf16le_z(data) {
        s
    } else {
        String::from_utf8_lossy(data).to_string()
    };

    Ok(ProcessEvent {
        utc_time: String::new(),
        process_guid: String::new(),
        process_id: 0,
        image: "powershell.exe".to_string(),
        file_version: String::new(),
        description: String::new(),
        product: String::new(),
        company: String::new(),
        command_line: truncate_script(&script_content, 4096),
        current_directory: String::new(),
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
        parent_image: String::new(),
        parent_command_line: String::new(),
    })
}

fn truncate_script(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...[truncated]", &s[..max_len])
    }
}

fn calculate_script_severity(script: &str) -> i32 {
    let lower = script.to_lowercase();

    // highly suspicious patterns
    let critical = [
        "invoke-mimikatz",
        "invoke-shellcode",
        "invoke-expression",
        "downloadstring",
        "downloadfile",
        "webclient",
        "bitstransfer",
        "invoke-obfuscation",
        "amsibypass",
        "disable-amsi",
        "frombase64string",
        "-enc ",
        "-encodedcommand",
        "reflection.assembly",
        "add-type",
        "dllimport",
        "virtualalloc",
        "createthread",
        "shellcode",
    ];

    for pattern in &critical {
        if lower.contains(pattern) {
            return 80;
        }
    }

    // suspicious patterns
    let suspicious = [
        "get-credential",
        "convertto-securestring",
        "invoke-command",
        "new-object",
        "system.net",
        "system.io",
        "hidden",
        "-windowstyle",
        "bypass",
        "unrestricted",
    ];

    for pattern in &suspicious {
        if lower.contains(pattern) {
            return 50;
        }
    }

    20
}
