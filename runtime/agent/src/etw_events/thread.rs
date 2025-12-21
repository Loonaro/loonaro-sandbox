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

// register handlers for injection-related events
pub fn register_thread_events(
    etw: &mut EtwSession,
    tx: mpsc::Sender<AgentMessage>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // Microsoft-Windows-Kernel-Process {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}
    let guid = Guid::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
    etw.enable_provider(guid);

    // event 3: thread start
    register_thread_start(etw, tx.clone(), ancillary.clone(), counter.clone(), guid);

    // event 4: thread end
    register_thread_end(etw, tx.clone(), ancillary.clone(), counter.clone(), guid);
}

fn register_thread_start(
    etw: &mut EtwSession,
    tx: mpsc::Sender<AgentMessage>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
    guid: Guid,
) {
    let mut event = Event::new(3, "Thread::Start".into());
    *event.extension_mut().provider_mut() = guid;

    event.add_callback(move |data: &EventData| -> Result<()> {
        *counter.borrow_mut() += 1;

        let payload = data.event_data();
        if let Ok(ev) = parse_thread_event(&payload) {
            // detect remote thread creation: source pid != target pid
            let is_remote = ev.process_id != ev.parent_process_id && ev.parent_process_id != 0;

            let category = if is_remote {
                SigmaCategory::CategoryCreateRemoteThread
            } else {
                // skip local thread creation (too noisy)
                return Ok(());
            };

            let mut timestamp = 0;
            ancillary.read(|a| timestamp = a.time());

            let msg = AgentMessage {
                payload: Some(agent_message::Payload::Event(MalwareEvent {
                    session_id: String::new(),
                    timestamp: filetime_to_rfc3339(timestamp),
                    severity: if is_remote { 60 } else { 0 },
                    category: category.into(),
                    event: Some(loonaro_models::sigma::malware_event::Event::Process(ev)),
                })),
            };
            let _ = tx.try_send(msg);
        }
        Ok(())
    });

    etw.add_event(event, None);
}

fn register_thread_end(
    etw: &mut EtwSession,
    tx: mpsc::Sender<AgentMessage>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
    guid: Guid,
) {
    let mut event = Event::new(4, "Thread::End".into());
    *event.extension_mut().provider_mut() = guid;

    let _tx = tx;
    let _ancillary = ancillary;

    event.add_callback(move |_data: &EventData| -> Result<()> {
        *counter.borrow_mut() += 1;
        // thread end events are not typically needed for security analysis
        // just count them for stats
        Ok(())
    });

    etw.add_event(event, None);
}

// thread start event layout:
// offset 0: process id (u32)
// offset 4: thread id (u32)
// offset 8: stack base (pointer)
// offset 16: stack limit (pointer)
// offset 24: user stack base (pointer)
// offset 32: user stack limit (pointer)
// offset 40: affinity (pointer)
// offset 48: win32 start addr (pointer)
// offset 56: teb base (pointer)
// offset 64: sub process tag (u32)
// offset 68: base priority (u8)
// offset 69: page priority (u8)
// offset 70: io priority (u8)
// offset 71: thread flags (u8)
fn parse_thread_event(data: &[u8]) -> Result<ProcessEvent, utils::ParseError> {
    if data.len() < 8 {
        return Err(utils::ParseError::Bounds);
    }

    let target_pid = utils::read_u32(data, 0)?;
    let thread_id = utils::read_u32(data, 4)?;

    // get win32 start address if available (indicates injection target)
    let start_addr = if data.len() >= 56 {
        let addr_bytes: [u8; 8] = data[48..56].try_into().unwrap_or([0u8; 8]);
        u64::from_le_bytes(addr_bytes)
    } else {
        0
    };

    // get source process (who created this thread) via windows api
    let source_pid = get_thread_creator_pid(thread_id);

    let target_image = get_process_image(target_pid);
    let source_image = get_process_image(source_pid);

    Ok(ProcessEvent {
        utc_time: String::new(),
        process_guid: format!(
            "{{{:08X}-{:04X}-{:04X}-0000-{:012X}}}",
            target_pid,
            thread_id,
            0,
            start_addr & 0xFFFFFFFFFFFF
        ),
        process_id: target_pid,
        image: target_image,
        file_version: String::new(),
        description: format!(
            "Thread {} created with start address 0x{:016X}",
            thread_id, start_addr
        ),
        product: String::new(),
        company: String::new(),
        command_line: String::new(),
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
        parent_process_id: source_pid,
        parent_image: source_image,
        parent_command_line: String::new(),
    })
}

fn get_thread_creator_pid(_tid: u32) -> u32 {
    // in etw, we don't directly get the creator pid
    // the "parent" in thread context is the process that owns the thread
    // for remote thread detection, we need to compare against original process
    // this is handled by checking if source != target in the callback
    // here we return 0 to indicate unknown source
    0
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
