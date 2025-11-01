#[derive(Debug)]
pub enum EventParseError {
    Pid,
    PPid,
    SidLength,
    ImageName,
    CommandLine,
    UniqueProcess,
    SessionId,
    ExitStatusField,
    DirectoryTableBase,
}
