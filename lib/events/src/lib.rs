mod error;
mod sid;

use crate::error::EventParseError;
use crate::sid::sid_length;
use minicbor::{Decode, Encode};
use one_collect::event::{EventData, EventFieldRef, EventFormat};
use std::cmp::PartialEq;

#[derive(Encode, Decode)]
pub enum EtwEvent {
    #[n(0)]
    SystemProcess(#[n(0)] ProcessEvent),
    #[n(1)]
    Sysmon,
}

#[derive(Encode, Decode)]
pub enum ProcessEvent {
    #[n(0)]
    ProcessCreate(#[n(0)] ProcessEventPayload),
    #[n(1)]
    ProcessTerminate(#[n(0)] ProcessEventPayload),
}

#[derive(Encode, Decode, Default, Debug)]
pub struct ProcessEventPayload {
    #[n(0)]
    unique_process_key: u32,
    #[n(1)]
    process_id: u32,
    #[n(2)]
    parent_process_id: u32,
    #[n(3)]
    session_id: u32,
    #[n(4)]
    exit_status: i32,
    #[n(5)]
    directory_table_base: u32,
    #[n(6)]
    user_sid: Vec<u8>,
    #[n(7)]
    image_file_name: Vec<u8>,
    #[n(8)]
    command_line: Vec<u8>,
}

impl ProcessEventPayload {
    pub fn as_bytes(&self) -> Vec<u8> {
        minicbor::to_vec(self).unwrap()
    }
}

pub struct ProcessEventFields {
    pub unique_process_key_field: EventFieldRef,
    pub pid_field: EventFieldRef,
    pub ppid_field: EventFieldRef,
    pub session_id_field: EventFieldRef,
    pub exit_status_field: EventFieldRef,
    pub directory_table_base_field: EventFieldRef,
    pub sid_field: EventFieldRef,
    pub name_field: EventFieldRef,
    pub cmd_field: EventFieldRef,
}
impl ProcessEventFields {
    pub fn new(fmt: &EventFormat) -> Self {
        Self {
            unique_process_key_field: fmt.get_field_ref_unchecked("UniqueProcessKey"),
            pid_field: fmt.get_field_ref_unchecked("ProcessId"),
            ppid_field: fmt.get_field_ref_unchecked("ParentId"),
            session_id_field: fmt.get_field_ref_unchecked("SessionId"),
            exit_status_field: fmt.get_field_ref_unchecked("ExitStatus"),
            directory_table_base_field: fmt.get_field_ref_unchecked("DirectoryTableBase"),
            sid_field: fmt.get_field_ref_unchecked("UserSID"),
            name_field: fmt.get_field_ref_unchecked("ImageFileName"),
            cmd_field: fmt.get_field_ref_unchecked("CommandLine"),
        }
    }
}

impl ProcessEventPayload {
    pub fn from_event_data(
        data: &EventData,
        fields: &ProcessEventFields,
    ) -> Result<Self, EventParseError> {
        let fmt = data.format();

        let data = data.event_data();

        let sid = fmt.get_field_unchecked(fields.sid_field);

        let unique_process_key = fmt
            .get_u32(fields.unique_process_key_field, data)
            .map_err(|_| EventParseError::Pid)?;
        let process_id = fmt
            .get_u32(fields.pid_field, data)
            .map_err(|_| EventParseError::Pid)?;
        let parent_process_id = fmt
            .get_u32(fields.ppid_field, data)
            .map_err(|_| EventParseError::PPid)?;
        let session_id = fmt
            .get_u32(fields.session_id_field, data)
            .map_err(|_| EventParseError::SessionId)?;
        let exit_status = fmt
            .get_u32(fields.exit_status_field, data)
            .map_err(|_| EventParseError::ExitStatusField)?;
        let directory_table_base = fmt
            .get_u32(fields.directory_table_base_field, data)
            .map_err(|_| EventParseError::DirectoryTableBase)?;

        let dynamic = &data[sid.offset..];
        let sid_length = sid_length(dynamic).map_err(|_| EventParseError::SidLength)?;
        let user_sid = dynamic[..sid_length].to_vec();

        let dynamic = &dynamic[sid_length..];
        let image_file_name = fmt.get_data(fields.name_field, dynamic);

        let dynamic = &dynamic[image_file_name.len()..];
        let command_line = fmt.get_data(fields.cmd_field, dynamic);

        Ok(Self {
            unique_process_key,
            process_id,
            parent_process_id,
            session_id,
            exit_status: exit_status as i32,
            directory_table_base,
            user_sid,
            image_file_name: image_file_name.to_owned(),
            command_line: command_line.to_owned(),
        })
    }
}

impl PartialEq for ProcessEventPayload {
    fn eq(&self, other: &Self) -> bool {
        self.unique_process_key == other.unique_process_key
            && self.process_id == other.process_id
            && self.parent_process_id == other.parent_process_id
            && self.session_id == other.session_id
            && self.exit_status == other.exit_status
            && self.directory_table_base == other.directory_table_base
            && self.user_sid == other.user_sid
            && self.image_file_name == other.image_file_name
    }
}

#[derive(Encode, Decode)]
struct Event {
    #[n(0)]
    payload: EtwEvent,
    #[n(1)]
    timestamp: u64,
}

impl Event {
    pub fn new(payload: EtwEvent, timestamp: u64) -> Self {
        Self { payload, timestamp }
    }
}

#[test]
fn serialize_deserialize() {
    let original_payload = ProcessEventPayload::default();
    let original_event = Event::new(
        EtwEvent::SystemProcess(ProcessEvent::ProcessCreate(original_payload)),
        123456789,
    );

    // pretend we are sending from the agent - SERIALIZE
    let raw_bytes = minicbor::to_vec(&original_event).unwrap();

    // pretend we are the host listening to the socket - DESERIALIZE
    let deserialized_event: Event = minicbor::decode(raw_bytes.as_slice()).unwrap();

    assert_eq!(original_event.timestamp, deserialized_event.timestamp)
}
