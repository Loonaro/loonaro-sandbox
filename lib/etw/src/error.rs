use thiserror::Error;
use crate::payload::ParseError;

#[derive(Error, Debug)]
pub enum LoonaroETWError {
    #[error("Failed to parse process event payload: {0}")]
    ProcessPayloadParse(#[from] ParseError),
}