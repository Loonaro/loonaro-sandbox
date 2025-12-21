//! pnp device events for usb and hardware detection
//! catches usb-based attack vectors and malware drops

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

pub fn register_pnp_events(
    etw: &mut EtwSession,
    tx: mpsc::Sender<AgentMessage>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // Microsoft-Windows-Kernel-PnP {9C205A39-1250-487D-ABD7-E831C6290539}
    let guid = Guid::from_u128(0x9C205A39_1250_487D_ABD7_E831C6290539);
    etw.enable_provider(guid);

    // device events
    let events = vec![(100, "DeviceArrival"), (101, "DeviceRemoval")];

    for (opcode, name) in events {
        let mut event = Event::new(opcode, format!("PnP::{}", name));
        *event.extension_mut().provider_mut() = guid;

        let tx_clone = tx.clone();
        let ancillary_clone = ancillary.clone();
        let counter_clone = counter.clone();

        event.add_callback(move |data: &EventData| -> Result<()> {
            *counter_clone.borrow_mut() += 1;

            let payload = data.event_data();
            if let Ok(pnp_event) = parse_pnp_event(&payload) {
                let mut timestamp = 0;
                ancillary_clone.read(|a| timestamp = a.time());

                let severity = if is_usb_device(&pnp_event.target_filename) {
                    30
                } else {
                    10
                };

                let msg = AgentMessage {
                    payload: Some(agent_message::Payload::Event(MalwareEvent {
                        session_id: String::new(),
                        timestamp: utils::filetime_to_rfc3339(timestamp),
                        severity,
                        category: SigmaCategory::CategoryDriverLoad.into(), // reuse driver category
                        event: Some(loonaro_models::sigma::malware_event::Event::File(pnp_event)),
                    })),
                };
                let _ = tx_clone.try_send(msg);
            }
            Ok(())
        });

        etw.add_event(event, None);
    }
}

fn parse_pnp_event(data: &[u8]) -> Result<FileEvent, utils::ParseError> {
    // device instance id
    let (device_id, _) = if let Ok(r) = utils::take_utf16le_z(data) {
        r
    } else {
        (String::new(), &[][..])
    };

    Ok(FileEvent {
        target_filename: device_id,
        image: String::new(),
        action: "DeviceEvent".to_string(),
        sha256: String::new(),
        user: String::new(),
        utc_time: String::new(),
        process_guid: String::new(),
        process_id: 0,
        creation_utc_time: String::new(),
    })
}

fn is_usb_device(device_id: &str) -> bool {
    let lower = device_id.to_lowercase();
    lower.contains("usb") || lower.contains("usbstor") || lower.contains("removable")
}
