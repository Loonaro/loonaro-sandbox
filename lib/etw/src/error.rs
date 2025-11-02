use thiserror::Error;
use crate::payload::process::{ProcessPayloadParseError};

#[derive(Error, Debug)]
pub enum LoonaroETWError {
    #[error("Failed to parse process event payload: {0:?}")]
    ProcessPayloadParse(#[from] ProcessPayloadParseError),
}