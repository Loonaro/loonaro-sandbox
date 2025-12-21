use crate::utils;
use loonaro_models::sigma::{
    agent_message, AgentMessage, MalwareEvent, RegistryEvent, SigmaCategory,
};
use one_collect::etw::{AncillaryData, EtwSession};
use one_collect::event::{Event, EventData};
use one_collect::Guid;
use one_collect::ReadOnly;
use std::cell::RefCell;
use std::rc::Rc;
use tokio::sync::mpsc;

pub fn register_registry(
    etw: &mut EtwSession,
    tx: mpsc::Sender<AgentMessage>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // Microsoft-Windows-Kernel-Registry {70eb4f03-c1de-4f73-a051-33d13d5413bd}
    let guid = Guid::from_u128(0x70eb4f03_c1de_4f73_a051_33d13d5413bd);
    etw.enable_provider(guid);

    // registry operations with sigma event type mapping
    let opcodes = vec![
        (
            10,
            "CreateKey",
            "CreateKey",
            SigmaCategory::CategoryRegistryAdd,
        ),
        (
            11,
            "OpenKey",
            "OpenKey",
            SigmaCategory::CategoryRegistryEvent,
        ),
        (
            12,
            "DeleteKey",
            "DeleteKey",
            SigmaCategory::CategoryRegistryDelete,
        ),
        (
            13,
            "QueryKey",
            "QueryKey",
            SigmaCategory::CategoryRegistryEvent,
        ),
        (
            14,
            "SetValue",
            "SetValue",
            SigmaCategory::CategoryRegistrySet,
        ),
        (
            15,
            "DeleteValue",
            "DeleteValue",
            SigmaCategory::CategoryRegistryDelete,
        ),
        (
            16,
            "QueryValue",
            "QueryValue",
            SigmaCategory::CategoryRegistryEvent,
        ),
        (
            17,
            "EnumerateKey",
            "EnumerateKey",
            SigmaCategory::CategoryRegistryEvent,
        ),
        (
            18,
            "EnumerateValueKey",
            "EnumerateValueKey",
            SigmaCategory::CategoryRegistryEvent,
        ),
        (
            22,
            "KCBCreate",
            "KCBCreate",
            SigmaCategory::CategoryRegistryEvent,
        ),
        (
            23,
            "KCBDelete",
            "KCBDelete",
            SigmaCategory::CategoryRegistryEvent,
        ),
        (27, "Close", "Close", SigmaCategory::CategoryRegistryEvent),
    ];

    for (opcode, action_name, event_type, category) in opcodes {
        let mut event = Event::new(opcode, format!("Registry::{}", action_name));
        *event.extension_mut().provider_mut() = guid;

        let ancillary_clone = ancillary.clone();
        let tx_clone = tx.clone();
        let counter_clone = counter.clone();
        let action_str = action_name.to_string();
        let event_type_str = event_type.to_string();

        event.add_callback(move |data: &EventData| -> anyhow::Result<()> {
            *counter_clone.borrow_mut() += 1;

            let payload = data.event_data();
            if let Ok(mut reg_event) = parse_registry_event(&payload, opcode as u8) {
                reg_event.action = action_str.clone();
                reg_event.event_type = event_type_str.clone();

                let mut timestamp = 0;
                ancillary_clone.read(|a| timestamp = a.time());

                let msg = AgentMessage {
                    payload: Some(agent_message::Payload::Event(MalwareEvent {
                        session_id: String::new(),
                        timestamp: filetime_to_rfc3339(timestamp),
                        severity: 0,
                        category: category.into(),
                        event: Some(loonaro_models::sigma::malware_event::Event::Registry(
                            reg_event,
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

// registry event payload layout varies by opcode
// common layout:
// offset 0-7: initial time (u64)
// offset 8-11: status (u32)
// offset 12-15: index (u32)
// offset 16-23: key handle (u64 on x64)
// offset 24+: key name (utf16-z)
// for setvalue: after key name comes value name, type, data
fn parse_registry_event(data: &[u8], opcode: u8) -> Result<RegistryEvent, utils::ParseError> {
    if data.len() < 24 {
        return Err(utils::ParseError::Bounds);
    }

    let status = utils::read_u32(data, 8)?;

    // skip header to get to key name
    let key_start = 24;
    let key_data = data.get(key_start..).ok_or(utils::ParseError::Bounds)?;
    let (key_name, rest) = utils::take_utf16le_z(key_data)?;

    // for value operations, extract value name and potentially data
    let (value_name, details) = if matches!(opcode, 14 | 15 | 16 | 18) {
        // setvalue, deletevalue, queryvalue, enumeratevaluekey
        if let Ok((vn, remaining)) = utils::take_utf16le_z(rest) {
            let details = if opcode == 14 && remaining.len() >= 4 {
                // setvalue: parse type and data
                let value_type = u32::from_le_bytes(remaining[0..4].try_into().unwrap_or([0u8; 4]));
                let data_preview = if remaining.len() > 8 {
                    format_registry_data(value_type, &remaining[8..])
                } else {
                    String::new()
                };
                format!("{}:{}", registry_type_name(value_type), data_preview)
            } else {
                String::new()
            };
            (vn, details)
        } else {
            (String::new(), String::new())
        }
    } else {
        (String::new(), format!("Status: 0x{:08X}", status))
    };

    // get process image that performed the registry operation
    let image = get_current_process_image();

    Ok(RegistryEvent {
        target_object: if value_name.is_empty() {
            key_name
        } else {
            format!("{}\\{}", key_name, value_name)
        },
        details,
        image,
        action: String::new(),
        user: String::new(),
        event_type: String::new(),
    })
}

fn registry_type_name(type_id: u32) -> &'static str {
    match type_id {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        _ => "REG_UNKNOWN",
    }
}

fn format_registry_data(type_id: u32, data: &[u8]) -> String {
    match type_id {
        1 | 2 | 6 => {
            // string types
            String::from_utf16_lossy(
                &data
                    .chunks_exact(2)
                    .take(128) // limit preview
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&c| c != 0)
                    .collect::<Vec<_>>(),
            )
        }
        4 => {
            // dword
            if data.len() >= 4 {
                format!(
                    "0x{:08X}",
                    u32::from_le_bytes(data[0..4].try_into().unwrap_or([0u8; 4]))
                )
            } else {
                String::new()
            }
        }
        11 => {
            // qword
            if data.len() >= 8 {
                format!(
                    "0x{:016X}",
                    u64::from_le_bytes(data[0..8].try_into().unwrap_or([0u8; 8]))
                )
            } else {
                String::new()
            }
        }
        3 => {
            // binary - hex preview
            let preview: String = data
                .iter()
                .take(32)
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");
            if data.len() > 32 {
                format!("{}...", preview)
            } else {
                preview
            }
        }
        _ => {
            format!("[{} bytes]", data.len())
        }
    }
}

fn get_current_process_image() -> String {
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetProcessImageFileNameW;
        use windows::Win32::System::Threading::GetCurrentProcessId;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            let pid = GetCurrentProcessId();
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                if !handle.is_invalid() {
                    let mut buffer = [0u16; 260];
                    let len = GetProcessImageFileNameW(handle, &mut buffer);
                    let _ = CloseHandle(handle);
                    if len > 0 {
                        return String::from_utf16_lossy(&buffer[..len as usize]);
                    }
                }
            }
        }
    }
    String::new()
}

fn filetime_to_rfc3339(filetime: u64) -> String {
    let seconds = filetime / 10_000_000;
    let nanos = (filetime % 10_000_000) * 100;
    let unix_seconds = (seconds as i64) - 11_644_473_600;
    chrono::DateTime::from_timestamp(unix_seconds, nanos as u32)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}
