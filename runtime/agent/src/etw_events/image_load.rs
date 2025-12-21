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

// dll/image load events from kernel-process
pub fn register_image_load(
    etw: &mut EtwSession,
    tx: mpsc::Sender<AgentMessage>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // Microsoft-Windows-Kernel-Process {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}
    let guid = Guid::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
    etw.enable_provider(guid);

    // event 5: image load
    let mut event = Event::new(5, "Image::Load".into());
    *event.extension_mut().provider_mut() = guid;

    let ancillary_clone = ancillary.clone();
    let tx_clone = tx.clone();
    let counter_clone = counter.clone();

    event.add_callback(move |data: &EventData| -> Result<()> {
        *counter_clone.borrow_mut() += 1;

        let payload = data.event_data();
        if let Ok(ev) = parse_image_load_event(&payload) {
            let mut timestamp = 0;
            ancillary_clone.read(|a| timestamp = a.time());

            // determine if this is a driver load (kernel mode) or user mode dll
            let category = if ev.image.to_lowercase().ends_with(".sys") {
                SigmaCategory::CategoryDriverLoad
            } else {
                SigmaCategory::CategoryImageLoad
            };

            let msg = AgentMessage {
                payload: Some(agent_message::Payload::Event(MalwareEvent {
                    session_id: String::new(),
                    timestamp: filetime_to_rfc3339(timestamp),
                    severity: 0,
                    category: category.into(),
                    event: Some(loonaro_models::sigma::malware_event::Event::Process(ev)),
                })),
            };
            let _ = tx_clone.try_send(msg);
        }
        Ok(())
    });

    etw.add_event(event, None);

    // event 6: image unload
    let mut unload_event = Event::new(6, "Image::Unload".into());
    *unload_event.extension_mut().provider_mut() = guid;

    let counter_unload = counter.clone();

    unload_event.add_callback(move |_data: &EventData| -> Result<()> {
        *counter_unload.borrow_mut() += 1;
        // image unload not typically needed
        Ok(())
    });

    etw.add_event(unload_event, None);
}

// image load event layout:
// offset 0: process id (u32)
// offset 4: image base (pointer - 8 bytes on x64)
// offset 12: image size (pointer - 8 bytes)
// offset 20: image checksum (u32)
// offset 24: timestamp (u32) - pe timestamp
// offset 28: signature level (u8)
// offset 29: signature type (u8)
// offset 30: reserved0 (u16)
// offset 32: filename (utf16-z)
fn parse_image_load_event(data: &[u8]) -> Result<ProcessEvent, utils::ParseError> {
    if data.len() < 32 {
        return Err(utils::ParseError::Bounds);
    }

    let pid = utils::read_u32(data, 0)?;

    let image_base = if data.len() >= 12 {
        u64::from_le_bytes(data[4..12].try_into().unwrap_or([0u8; 8]))
    } else {
        0
    };

    let image_size = if data.len() >= 20 {
        u64::from_le_bytes(data[12..20].try_into().unwrap_or([0u8; 8]))
    } else {
        0
    };

    let checksum = utils::read_u32(data, 20).unwrap_or(0);
    let pe_timestamp = utils::read_u32(data, 24).unwrap_or(0);
    let sig_level = if data.len() > 28 { data[28] } else { 0 };
    let sig_type = if data.len() > 29 { data[29] } else { 0 };

    // filename starts at offset 32
    let filename_data = data.get(32..).ok_or(utils::ParseError::Bounds)?;
    let (image_path, _) = utils::take_utf16le_z(filename_data)?;

    let normalized_path = normalize_device_path(&image_path);
    let process_image = get_process_image(pid);

    Ok(ProcessEvent {
        utc_time: String::new(),
        process_guid: String::new(),
        process_id: pid,
        image: normalized_path.clone(),
        file_version: String::new(),
        description: format!(
            "Loaded at 0x{:016X}, size={}, checksum=0x{:08X}, sig_level={}, sig_type={}",
            image_base, image_size, checksum, sig_level, sig_type
        ),
        product: String::new(),
        company: String::new(),
        command_line: process_image, // store host process in command_line for now
        current_directory: String::new(),
        user: String::new(),
        logon_guid: String::new(),
        logon_id: format!("{}", pe_timestamp), // store pe timestamp
        terminal_session_id: 0,
        integrity_level: signature_level_to_string(sig_level),
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

fn signature_level_to_string(level: u8) -> String {
    match level {
        0 => "Unchecked".to_string(),
        1 => "Unsigned".to_string(),
        2 => "Enterprise".to_string(),
        3 => "Custom1".to_string(),
        4 => "Authenticode".to_string(),
        5 => "Custom2".to_string(),
        6 => "Store".to_string(),
        7 => "Custom3".to_string(),
        8 => "Antimalware".to_string(),
        11 => "Custom4".to_string(),
        12 => "Microsoft".to_string(),
        14 => "Custom5".to_string(),
        15 => "DynamicCodegen".to_string(),
        16 => "Windows".to_string(),
        18 => "Custom6".to_string(),
        19 => "WindowsTCB".to_string(),
        20 => "Custom7".to_string(),
        _ => format!("Level{}", level),
    }
}

fn normalize_device_path(path: &str) -> String {
    if !path.starts_with("\\Device\\") {
        return path.to_string();
    }

    #[cfg(windows)]
    {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

        for drive in b'A'..=b'Z' {
            let drive_letter = format!("{}:", drive as char);
            let mut target_path = [0u16; 260];

            unsafe {
                let drive_wide: Vec<u16> = drive_letter
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
                let result = QueryDosDeviceW(PCWSTR(drive_wide.as_ptr()), Some(&mut target_path));

                if result > 0 {
                    let device_path = String::from_utf16_lossy(&target_path[..result as usize]);
                    let device_path = device_path.trim_end_matches('\0');

                    if path.starts_with(device_path) {
                        return path.replacen(device_path, &drive_letter, 1);
                    }
                }
            }
        }
    }

    path.to_string()
}

fn get_process_image(pid: u32) -> String {
    if pid == 0 {
        return String::new();
    }

    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetProcessImageFileNameW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                if !handle.is_invalid() {
                    let mut buffer = [0u16; 260];
                    let len = GetProcessImageFileNameW(handle, &mut buffer);
                    let _ = CloseHandle(handle);
                    if len > 0 {
                        let path = String::from_utf16_lossy(&buffer[..len as usize]);
                        return normalize_device_path(&path);
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
