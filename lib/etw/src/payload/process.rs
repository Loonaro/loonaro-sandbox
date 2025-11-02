use crate::error::LoonaroETWError;
use crate::payload::FieldProvider;
use crate::sid::sid_length;
use one_collect::event::{EventField, EventFieldRef, EventFormat, LocationType};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProcessPayloadParseError {
    #[error("Failed to parse process payload field: Pid")]
    Pid,
    #[error("Failed to parse process payload field: PPid")]
    PPid,
    #[error("Failed to parse process payload field: Sid")]
    Sid,
    #[error("Failed to parse process payload field: ImageName")]
    ImageName,
    #[error("Failed to parse process payload field: CommandLine")]
    CommandLine,
        #[error("Failed to parse process payload field: UniqueProcessKey")]
    UniqueProcess,
    #[error("Failed to parse process payload field: SessionId")]
    SessionId,
    #[error("Failed to parse process payload field: ExitStatusField")]
    ExitStatusField,
    #[error("Failed to parse process payload field: DirectoryTableBase")]
    DirectoryTableBase,
}

pub struct ProcessPayloadFieldRefs {
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

impl ProcessPayloadFieldRefs {
    pub fn new(format: &EventFormat) -> Self {
        Self {
            unique_process_key_field: format.get_field_ref_unchecked("UniqueProcessKey"),
            pid_field: format.get_field_ref_unchecked("ProcessId"),
            ppid_field: format.get_field_ref_unchecked("ParentId"),
            session_id_field: format.get_field_ref_unchecked("SessionId"),
            exit_status_field: format.get_field_ref_unchecked("ExitStatus"),
            directory_table_base_field: format.get_field_ref_unchecked("DirectoryTableBase"),
            sid_field: format.get_field_ref_unchecked("UserSID"),
            name_field: format.get_field_ref_unchecked("ImageFileName"),
            cmd_field: format.get_field_ref_unchecked("CommandLine"),
        }
    }
}

pub struct ProcessPayloadFieldsProvider {
    format: EventFormat,
    fields: ProcessPayloadFieldRefs,
}

impl ProcessPayloadFieldsProvider {
    pub fn new() -> Self {
        let mut offset: usize = 0;
        let mut len: usize;

        let mut format = EventFormat::new();

        len = 8;
        format.add_field(EventField::new(
            "UniqueProcessKey".into(),
            "u64".into(),
            LocationType::Static,
            offset,
            len,
        ));
        offset += len;

        len = 4;
        format.add_field(EventField::new(
            "ProcessId".into(),
            "u32".into(),
            LocationType::Static,
            offset,
            len,
        ));
        offset += len;

        format.add_field(EventField::new(
            "ParentId".into(),
            "u32".into(),
            LocationType::Static,
            offset,
            len,
        ));
        offset += len;

        format.add_field(EventField::new(
            "SessionId".into(),
            "u32".into(),
            LocationType::Static,
            offset,
            len,
        ));
        offset += len;

        format.add_field(EventField::new(
            "ExitStatus".into(),
            "s32".into(),
            LocationType::Static,
            offset,
            len,
        ));
        offset += len;

        len = 8;
        format.add_field(EventField::new(
            "DirectoryTableBase".into(),
            "u64".into(),
            LocationType::Static,
            offset,
            len,
        ));
        offset += len;

        len = 4;
        format.add_field(EventField::new(
            "Flags".into(),
            "u32".into(),
            LocationType::Static,
            offset,
            len,
        ));
        offset += len;

        /* Dynamically sized after this */
        len = 0;
        format.add_field(EventField::new(
            "UserSID".into(),
            "object".into(),
            LocationType::Static,
            offset,
            len,
        ));

        /* Only first dynamic data will have offset */
        let offset = 0;
        format.add_field(EventField::new(
            "ImageFileName".into(),
            "string".into(),
            LocationType::StaticString,
            offset,
            len,
        ));

        format.add_field(EventField::new(
            "CommandLine".into(),
            "string".into(),
            LocationType::StaticUTF16String,
            offset,
            len,
        ));

        Self {
            fields: ProcessPayloadFieldRefs::new(&format),
            format,
        }
    }
}

impl FieldProvider<ProcessEventPayload> for ProcessPayloadFieldsProvider {
    fn event_data(&self, data: &[u8]) -> Result<ProcessEventPayload, LoonaroETWError> {
        let sid = self.format.get_field_unchecked(self.fields.sid_field);

        let unique_process_key = self
            .format
            .get_u32(self.fields.unique_process_key_field, data)
            .map_err(|_| ProcessPayloadParseError::Pid)?;
        let process_id = self
            .format
            .get_u32(self.fields.pid_field, data)
            .map_err(|_| ProcessPayloadParseError::Pid)?;
        let parent_process_id = self
            .format
            .get_u32(self.fields.ppid_field, data)
            .map_err(|_| ProcessPayloadParseError::PPid)?;
        let session_id = self
            .format
            .get_u32(self.fields.session_id_field, data)
            .map_err(|_| ProcessPayloadParseError::SessionId)?;
        let exit_status = self
            .format
            .get_u32(self.fields.exit_status_field, data)
            .map_err(|_| ProcessPayloadParseError::ExitStatusField)?;
        let directory_table_base = self
            .format
            .get_u32(self.fields.directory_table_base_field, data)
            .map_err(|_| ProcessPayloadParseError::DirectoryTableBase)?;

        let dynamic = &data[sid.offset..];
        let sid_length = sid_length(dynamic).map_err(|_| ProcessPayloadParseError::Sid)?;
        if dynamic.len() < sid_length {
            return Err(LoonaroETWError::ProcessPayloadParse(
                ProcessPayloadParseError::Sid,
            ));
        }

        let user_sid = dynamic[..sid_length].to_vec();

        let dynamic = &dynamic[sid_length..];
        let image_file_name = self.format.get_data(self.fields.name_field, dynamic);

        let dynamic = &dynamic[image_file_name.len()..];
        let command_line = self.format.get_data(self.fields.cmd_field, dynamic);

        Ok(ProcessEventPayload {
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

#[derive(Default, Debug)]
pub struct ProcessEventPayload {
    unique_process_key: u32,
    process_id: u32,
    parent_process_id: u32,
    session_id: u32,
    exit_status: i32,
    directory_table_base: u32,
    user_sid: Vec<u8>,
    image_file_name: Vec<u8>,
    command_line: Vec<u8>,
}

impl ProcessEventPayload {
    pub fn pid(&self) -> u32 {
        self.process_id
    }

    pub fn ppid(&self) -> u32 {
        self.parent_process_id
    }

    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    pub fn exit_status(&self) -> i32 {
        self.exit_status
    }

    pub fn directory_table_base(&self) -> u32 {
        self.directory_table_base
    }

    pub fn image(&self) -> String {
        String::from_utf8_lossy(&self.image_file_name).to_string()
    }

    pub fn cmd(&self) -> String {
        String::from_utf8_lossy(&self.command_line).to_string()
    }
}
