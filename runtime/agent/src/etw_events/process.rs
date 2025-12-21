use crate::cache;
use crate::utils;
use loonaro_models::sigma::{
    agent_message, AgentMessage, MalwareEvent, ProcessEvent, SigmaCategory,
};
use one_collect::etw::{AncillaryData, EtwSession};
use one_collect::event::{Event, EventData};
use one_collect::Guid;
use one_collect::ReadOnly;
use std::collections::HashMap;
use std::rc::Rc;
use tokio::sync::mpsc;

const OFF_PID: usize = 8;
const OFF_PPID: usize = 12;
const OFF_SESSION_ID: usize = 16;
const OFF_DYNAMIC: usize = 36;

pub fn register_process(
    etw: &mut EtwSession,
    tx: mpsc::Sender<AgentMessage>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<std::cell::RefCell<u64>>,
) {
    // Microsoft-Windows-Kernel-Process {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}
    let process_guid = Guid::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
    etw.enable_provider(process_guid);

    let events = vec![
        (1, "Start", SigmaCategory::CategoryProcessCreation),
        (2, "End", SigmaCategory::CategoryProcessTermination),
    ];

    // process cache: pid -> (image, command_line, process_guid)
    let process_cache: Rc<std::cell::RefCell<HashMap<u32, (String, String, String)>>> =
        Rc::new(std::cell::RefCell::new(HashMap::new()));

    for (opcode, name, category) in events {
        let mut event = Event::new(opcode, format!("Process::{}", name));
        *event.extension_mut().provider_mut() = process_guid;

        let ancillary_clone = ancillary.clone();
        let tx_clone = tx.clone();
        let counter_clone = counter.clone();
        let cache_clone = process_cache.clone();

        event.add_callback(move |data: &EventData| -> anyhow::Result<()> {
            *counter_clone.borrow_mut() += 1;

            let payload = data.event_data();
            if let Ok(mut proc_event) = parse_process_event(&payload) {
                let mut timestamp = 0;
                ancillary_clone.read(|a| timestamp = a.time());
                let timestamp_str = utils::filetime_to_rfc3339(timestamp);

                // generate process guid
                proc_event.process_guid =
                    utils::generate_process_guid(timestamp, proc_event.process_id);
                proc_event.utc_time = timestamp_str.clone();

                // cache/lookup logic
                {
                    let mut local_cache = cache_clone.borrow_mut();
                    let global_cache = cache::get_cache();

                    if opcode == 1 {
                        // process start: cache for parent resolution and cross-handler lookup
                        local_cache.insert(
                            proc_event.process_id,
                            (
                                proc_event.image.clone(),
                                proc_event.command_line.clone(),
                                proc_event.process_guid.clone(),
                            ),
                        );
                        // store in global cache for file/network/registry handlers
                        global_cache.store_process_info(
                            proc_event.process_id,
                            proc_event.image.clone(),
                            proc_event.user.clone(),
                        );
                        // resolve parent from local cache
                        if let Some((parent_img, parent_cmd, parent_guid)) =
                            local_cache.get(&proc_event.parent_process_id)
                        {
                            proc_event.parent_image = parent_img.clone();
                            proc_event.parent_command_line = parent_cmd.clone();
                            proc_event.parent_process_guid = parent_guid.clone();
                        }
                    } else {
                        // process end: remove from both caches
                        local_cache.remove(&proc_event.process_id);
                        global_cache.invalidate_process(proc_event.process_id);
                    }
                }

                // async enrichment for process creation
                if opcode == 1 {
                    let tx_inner = tx_clone.clone();
                    let image_path = proc_event.image.clone();
                    let mut final_event = proc_event;

                    tokio::spawn(async move {
                        // hash the executable using spawn_blocking to avoid blocking async runtime
                        let normalized_path = cache::get_cache().normalize_path(&image_path);
                        let path_clone = normalized_path.clone();

                        if let Ok(Some(hashes)) = tokio::task::spawn_blocking(move || {
                            cache::get_cache().get_file_hashes(&path_clone)
                        })
                        .await
                        {
                            final_event.md5 = hashes.md5;
                            final_event.sha1 = hashes.sha1;
                            final_event.sha256 = hashes.sha256;
                        }

                        let msg = AgentMessage {
                            payload: Some(agent_message::Payload::Event(MalwareEvent {
                                session_id: String::new(),
                                timestamp: timestamp_str,
                                severity: 0,
                                category: category.into(),
                                event: Some(loonaro_models::sigma::malware_event::Event::Process(
                                    final_event,
                                )),
                            })),
                        };
                        let _ = tx_inner.send(msg).await;
                    });
                } else {
                    // terminate: send immediately
                    let msg = AgentMessage {
                        payload: Some(agent_message::Payload::Event(MalwareEvent {
                            session_id: String::new(),
                            timestamp: timestamp_str,
                            severity: 0,
                            category: category.into(),
                            event: Some(loonaro_models::sigma::malware_event::Event::Process(
                                proc_event,
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

fn parse_process_event(data: &[u8]) -> Result<ProcessEvent, utils::ParseError> {
    if data.len() < OFF_DYNAMIC {
        return Err(utils::ParseError::Bounds);
    }

    let pid = utils::read_u32(data, OFF_PID)?;
    let ppid = utils::read_u32(data, OFF_PPID)?;
    let session_id = utils::read_u32(data, OFF_SESSION_ID).unwrap_or(0);

    let mut tail = data.get(OFF_DYNAMIC..).ok_or(utils::ParseError::Bounds)?;

    // sid - use cached lookup
    let (sid_bytes, rest) = utils::take_sid(tail)?;
    let user = cache::get_cache().get_user_from_sid(sid_bytes);
    tail = rest;

    // image filename (utf-8 c-string from kernel)
    let (image_path, rest) = utils::take_utf8_string(tail)?;
    tail = rest;

    // command line (utf-16le null-terminated)
    let (command_line, _) = utils::take_utf16le_z(tail)?;

    // normalize device path using cache
    let normalized_image = cache::get_cache().normalize_path(&image_path);

    // get additional info from windows apis if pid is valid
    let (integrity_level, _logon_id) = if pid > 0 {
        utils::get_process_info_live(pid)
    } else {
        (String::new(), String::new())
    };

    Ok(ProcessEvent {
        image: normalized_image,
        command_line,
        process_id: pid,
        parent_process_id: ppid,
        parent_image: String::new(),
        parent_command_line: String::new(),
        user,
        sha256: String::new(),
        integrity_level,
        utc_time: String::new(),
        process_guid: String::new(),
        file_version: String::new(),
        description: String::new(),
        product: String::new(),
        company: String::new(),
        current_directory: String::new(),
        logon_guid: String::new(),
        logon_id: String::new(),
        terminal_session_id: session_id,
        md5: String::new(),
        sha1: String::new(),
        imphash: String::new(),
        parent_process_guid: String::new(),
    })
}
