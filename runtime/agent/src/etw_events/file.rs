use crate::cache;
use crate::utils;
use loonaro_models::sigma::{agent_message, AgentMessage, FileEvent, MalwareEvent, SigmaCategory};
use one_collect::etw::{AncillaryData, EtwSession};
use one_collect::event::{Event, EventData};
use one_collect::Guid;
use one_collect::ReadOnly;
use std::cell::RefCell;
use std::rc::Rc;
use tokio::sync::mpsc;

const OFF_TTID: usize = 16;
const OFF_OPEN_PATH: usize = 32;

pub fn register_file(
    etw: &mut EtwSession,
    tx: mpsc::Sender<AgentMessage>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // Microsoft-Windows-Kernel-File {edd08927-9cc4-4e65-b970-c2560fb5c289}
    let file_guid = Guid::from_u128(0xedd08927_9cc4_4e65_b970_c2560fb5c289);
    etw.enable_provider(file_guid);

    // file operations: (opcode, name, category, should_hash, invalidates_cache)
    // anti-evasion: write/delete/rename/setinfo all invalidate cache to defeat timestomping
    let file_ops = vec![
        (12, "Create", SigmaCategory::CategoryFileEvent, true, false),
        (15, "Delete", SigmaCategory::CategoryFileDelete, false, true),
        (14, "Write", SigmaCategory::CategoryFileChange, false, true),
        (16, "Rename", SigmaCategory::CategoryFileRename, false, true),
        (
            17,
            "SetInfo",
            SigmaCategory::CategoryFileChange,
            false,
            true,
        ),
    ];

    for (opcode, action_name, category, should_hash, invalidates_cache) in file_ops {
        let mut event = Event::new(opcode, format!("FileIo::{}", action_name));
        *event.extension_mut().provider_mut() = file_guid;
        event.set_no_callstack_flag();

        let ancillary_clone = ancillary.clone();
        let tx_clone = tx.clone();
        let counter_clone = counter.clone();
        let action_str = action_name.to_string();

        event.add_callback(move |data: &EventData| -> anyhow::Result<()> {
            *counter_clone.borrow_mut() += 1;

            let payload = data.event_data();
            if let Ok(mut file_event) = parse_file_event(&payload) {
                file_event.action = action_str.clone();
                let enrichment_cache = cache::get_cache();

                // anti-evasion: invalidate cache on any file modification
                // this defeats timestomping - we don't trust mtime alone
                if invalidates_cache && !file_event.target_filename.is_empty() {
                    enrichment_cache.invalidate_file_path(&file_event.target_filename);
                }

                // hash file for creates using cached api
                if should_hash && !file_event.target_filename.is_empty() {
                    if let Some(hashes) =
                        enrichment_cache.get_file_hashes(&file_event.target_filename)
                    {
                        file_event.sha256 = hashes.sha256;
                    }
                }

                let mut timestamp = 0;
                ancillary_clone.read(|a| timestamp = a.time());
                let ts_str = utils::filetime_to_rfc3339(timestamp);
                file_event.utc_time = ts_str.clone();

                let msg = AgentMessage {
                    payload: Some(agent_message::Payload::Event(MalwareEvent {
                        session_id: String::new(),
                        timestamp: ts_str,
                        severity: 0,
                        category: category.into(),
                        event: Some(loonaro_models::sigma::malware_event::Event::File(
                            file_event,
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

fn parse_file_event(data: &[u8]) -> Result<FileEvent, utils::ParseError> {
    if data.len() < OFF_OPEN_PATH {
        return Err(utils::ParseError::Bounds);
    }

    // get pid from thread id
    let tid = utils::read_u32(data, OFF_TTID).unwrap_or(0);
    let pid = utils::get_pid_from_tid(tid);

    let path_data = data.get(OFF_OPEN_PATH..).ok_or(utils::ParseError::Bounds)?;
    let (file_path, _) = utils::take_utf16le_z(path_data)?;

    // normalize device path using cached drive map
    let cache = cache::get_cache();
    let normalized_path = cache.normalize_path(&file_path);

    // get process info from cache (etw-captured, not queried)
    let (image, user) = cache
        .get_process_info(pid)
        .map(|p| (p.image, p.user))
        .unwrap_or_default();

    Ok(FileEvent {
        target_filename: normalized_path,
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
