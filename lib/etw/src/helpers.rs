// Decoding helpers for ETW payloads

use crate::payload::ParseError;

/// Decode a UTF-16LE, null-terminated string from a byte slice.
/// Returns an owned `String`. Stops at the first 0x0000 unit or end of input.
pub fn utf16le_null_terminated(bytes: &[u8]) -> Result<String, ()> {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    let mut iter = bytes.chunks_exact(2);
    while let Some(pair) = iter.next() {
        let u = u16::from_le_bytes([pair[0], pair[1]]);
        if u == 0 { break; }
        units.push(u);
    }
    String::from_utf16(&units).map_err(|_| ())
}

/// Returns a view of the bytes up to the first NUL (0x00) if present, otherwise the entire slice.
pub fn cstr_bytes(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(i) => &bytes[..i],
        None => bytes,
    }
}

/// Returns the length of the SID in bytes.
pub fn sid_length(data: &[u8]) -> Result<usize, ()> {
    const PTR_SIZE: usize = size_of::<usize>();
    let mut sid_size: usize = PTR_SIZE;

    if data.len() < 8 {
        return Err(());
    }

    let sid = u64::from_ne_bytes(data[..8].try_into().map_err(|_| ())?);

    if sid != 0 {
        let offset = PTR_SIZE * 2;
        let start = offset + 1;

        if data.len() < start {
            return Err(());
        }

        let auth_count = data[start..][0] as usize;
        sid_size = offset + 8 + (auth_count * 4);
    }

    Ok(sid_size)
}

/// Take the SID slice from the front of `bytes`, returning `(sid, rest)`.
/// Errors if the computed SID length exceeds the available bytes.
pub fn take_sid(bytes: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    let sid_len = sid_length(bytes).map_err(|_| ParseError::Sid)?;
    if bytes.len() < sid_len {
        return Err(ParseError::Bounds("SID"));
    }
    Ok((&bytes[..sid_len], &bytes[sid_len..]))
}

/// Take a utf8 string. Returns `(view, rest)`,
/// where `rest` starts after the NUL if present, otherwise empty.
pub fn take_utf8_string(bytes: &[u8]) -> Result<(String, &[u8]), ParseError> {
    let cstr_view = cstr_bytes(bytes);
    let s = std::str::from_utf8(cstr_view)
        .map_err(|_| ParseError::Utf8("UTF-8 string"))?
        .to_string();
    let rest = if cstr_view.len() < bytes.len() {
        &bytes[cstr_view.len() + 1..]
    } else {
        &[]
    };

    Ok((s, rest))
}

/// Take a UTF-16LE, null-terminated string. Returns `(string, rest)`.
/// If no terminator is found, consumes the whole slice and returns `rest = &[]`.
pub fn take_utf16le_z(bytes: &[u8]) -> Result<(String, &[u8]), ParseError> {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if u == 0 {
            let s = String::from_utf16(&units).map_err(|_| ParseError::Utf16)?;
            let rest = if i + 2 <= bytes.len() { &bytes[i + 2..] } else { &[] };
            return Ok((s, rest));
        }
        units.push(u);
        i += 2;
    }
    // No terminator; decode what we have.
    let s = String::from_utf16(&units).map_err(|_| ParseError::Utf16)?;
    Ok((s, &[]))
}


#[inline]
pub fn read_u32(data: &[u8], off: usize) -> Result<u32, ParseError> {
    let bytes = data
        .get(off..off + 4)
        .ok_or(ParseError::Bounds("u32"))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

#[inline]
pub fn read_u64(data: &[u8], off: usize) -> Result<u64, ParseError> {
    let bytes = data
        .get(off..off + 8)
        .ok_or(ParseError::Bounds("u64"))?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}