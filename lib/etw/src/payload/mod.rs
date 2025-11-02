pub mod process;

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("Out-of-bounds while reading {0}")]
    Bounds(&'static str),
    #[error("Invalid UTF-16 string")] 
    Utf16,
    #[error("Invalid UTF-8 in {0}")]
    Utf8(&'static str),
    #[error("Invalid SID")] 
    Sid,
    #[error("Failed to parse field: {0}")]
    Field(&'static str),
}

pub trait WithField<T> {
    fn with_field(self, name: &'static str) -> Result<T, ParseError>;
}

impl<T, E> WithField<T> for Result<T, E> {
    fn with_field(self, name: &'static str) -> Result<T, ParseError> {
        self.map_err(|_| ParseError::Field(name))
    }
}
