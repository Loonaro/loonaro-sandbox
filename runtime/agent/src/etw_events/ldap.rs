//! ldap query events for active directory reconnaissance detection
//! catches ad enumeration used by ransomware and apt groups

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

pub fn register_ldap_events(
    etw: &mut EtwSession,
    tx: mpsc::Sender<AgentMessage>,
    ancillary: ReadOnly<AncillaryData>,
    counter: Rc<RefCell<u64>>,
) {
    // Microsoft-Windows-LDAP-Client {099614A5-5DD7-4788-8BC9-E29F43DB28FC}
    let guid = Guid::from_u128(0x099614A5_5DD7_4788_8BC9_E29F43DB28FC);
    etw.enable_provider(guid);

    // ldap search start event
    let mut event = Event::new(30, "LDAP::SearchStart".into());
    *event.extension_mut().provider_mut() = guid;

    let tx_clone = tx.clone();
    let ancillary_clone = ancillary.clone();
    let counter_clone = counter.clone();

    event.add_callback(move |data: &EventData| -> Result<()> {
        *counter_clone.borrow_mut() += 1;

        let payload = data.event_data();
        if let Ok(ldap_event) = parse_ldap_event(&payload) {
            // report suspicious queries
            if is_suspicious_ldap(&ldap_event.command_line) {
                let mut timestamp = 0;
                ancillary_clone.read(|a| timestamp = a.time());

                let msg = AgentMessage {
                    payload: Some(agent_message::Payload::Event(MalwareEvent {
                        session_id: String::new(),
                        timestamp: utils::filetime_to_rfc3339(timestamp),
                        severity: calculate_ldap_severity(&ldap_event.command_line) as u32,
                        category: SigmaCategory::CategoryProcessAccess.into(),
                        event: Some(loonaro_models::sigma::malware_event::Event::Process(
                            ldap_event,
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

fn parse_ldap_event(data: &[u8]) -> Result<ProcessEvent, utils::ParseError> {
    // extract ldap filter/query from event data
    let query = if let Ok((s, _)) = utils::take_utf16le_z(data) {
        s
    } else {
        String::new()
    };

    Ok(ProcessEvent {
        utc_time: String::new(),
        process_guid: String::new(),
        process_id: 0,
        image: "LDAP".to_string(),
        file_version: String::new(),
        description: "LDAP Query".to_string(),
        product: String::new(),
        company: String::new(),
        command_line: query, // ldap filter stored here
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

fn is_suspicious_ldap(query: &str) -> bool {
    let lower = query.to_lowercase();

    let patterns = [
        "samaccounttype",
        "admincount=1",
        "serviceprincipalname",
        "msds-allowedtodelegateto",
        "useraccountcontrol",
        "domainadmins",
        "enterprise admins",
        "krbtgt",
        "laps",
        "gpp_autologon",
        "unicodepwd",
        "trustedforidelegation",
    ];

    for p in &patterns {
        if lower.contains(p) {
            return true;
        }
    }

    false
}

fn calculate_ldap_severity(query: &str) -> i32 {
    let lower = query.to_lowercase();

    if lower.contains("admincount=1") || lower.contains("krbtgt") {
        return 80;
    }
    if lower.contains("serviceprincipalname") || lower.contains("domainadmins") {
        return 70;
    }

    50
}
