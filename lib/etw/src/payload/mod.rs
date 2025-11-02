use crate::error::LoonaroETWError;

pub mod process;

pub trait FieldProvider<T> {
    fn event_data(&self, data: &[u8]) -> Result<T, LoonaroETWError>;
}
