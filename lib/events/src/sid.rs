use crate::error::EventParseError;

/// Returns the length of the SID in bytes.
pub fn sid_length(data: &[u8]) -> Result<usize, EventParseError> {
    const PTR_SIZE: usize = std::mem::size_of::<usize>();
    let mut sid_size: usize = PTR_SIZE;

    if data.len() < 8 {
        return Err(EventParseError::SidLength);
    }

    let sid = u64::from_ne_bytes(data[..8].try_into().map_err(|_| EventParseError::SidLength)?);

    if sid != 0 {
        let offset = PTR_SIZE * 2;
        let start = offset + 1;

        if data.len() < start {
            return Err(EventParseError::SidLength);
        }

        let auth_count = data[start..][0] as usize;
        sid_size = offset + 8 + (auth_count * 4);
    }

    Ok(sid_size)
}
