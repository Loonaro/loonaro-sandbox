mod error;
pub mod payload;
mod sid;

use crate::payload::process::ProcessEventPayload;
use minicbor::{Decode, Encode};
use one_collect::etw::AncillaryData;

#[derive(Encode, Decode, Debug, PartialEq, Eq)]
pub enum EtwEvent {
    #[n(0)]
    SystemProcess(#[n(0)] ProcessEvent),
    #[n(1)]
    Sysmon,
}

#[derive(Encode, Decode, Debug, PartialEq, Eq)]
pub enum ProcessEvent {
    #[n(0)]
    ProcessCreate,
    #[n(1)]
    ProcessTerminate,
}

#[derive(Debug)]
pub enum EventPayload {
    Process(ProcessEventPayload),
}

#[derive(Encode, Decode, Debug, PartialEq, Eq)]
pub struct EventHeader {
    #[n(0)]
    event_type: EtwEvent,
    #[n(1)]
    timestamp: u64,
    #[n(2)]
    pid: u32,
    #[n(3)]
    tid: u32,
}
impl EventHeader {
    pub fn from_ancillary(value: &AncillaryData, event_type: EtwEvent) -> Self {
        Self {
            event_type,
            timestamp: value.time(),
            pid: value.pid(),
            tid: value.tid(),
        }
    }

    pub fn event_type(&self) -> &EtwEvent {
        &self.event_type
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

#[derive(Debug)]
pub struct Event {
    header: EventHeader,
    payload: EventPayload,
}

impl Event {
    pub fn new(event_header: EventHeader, payload: EventPayload) -> Self {
        Self {
            header: event_header,
            payload,
        }
    }

    pub fn payload(&self) -> &EventPayload {
        &self.payload
    }

    pub fn header(&self) -> &EventHeader {
        &self.header
    }
}
