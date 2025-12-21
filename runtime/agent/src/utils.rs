//! parsing and enrichment utilities for etw event handlers

use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum ParseError {
    Bounds,
    Utf8,
    Utf16,
    Sid,
}

// === parsing utilities ===

pub fn cstr_bytes(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|&b| b == 0) {
        Some(i) => &bytes[..i],
        None => bytes,
    }
}

pub fn sid_length(data: &[u8]) -> Result<usize, ()> {
    const PTR_SIZE: usize = std::mem::size_of::<usize>();
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

pub fn take_sid(bytes: &[u8]) -> Result<(&[u8], &[u8]), ParseError> {
    let sid_len = sid_length(bytes).map_err(|_| ParseError::Sid)?;
    if bytes.len() < sid_len {
        return Err(ParseError::Bounds);
    }
    Ok((&bytes[..sid_len], &bytes[sid_len..]))
}

pub fn take_utf8_string(bytes: &[u8]) -> Result<(String, &[u8]), ParseError> {
    let cstr_view = cstr_bytes(bytes);
    let s = std::str::from_utf8(cstr_view)
        .map_err(|_| ParseError::Utf8)?
        .to_string();
    let rest = if cstr_view.len() < bytes.len() {
        &bytes[cstr_view.len() + 1..]
    } else {
        &[]
    };
    Ok((s, rest))
}

pub fn take_utf16le_z(bytes: &[u8]) -> Result<(String, &[u8]), ParseError> {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if u == 0 {
            let s = String::from_utf16(&units).map_err(|_| ParseError::Utf16)?;
            let rest = if i + 2 <= bytes.len() {
                &bytes[i + 2..]
            } else {
                &[]
            };
            return Ok((s, rest));
        }
        units.push(u);
        i += 2;
    }
    let s = String::from_utf16(&units).map_err(|_| ParseError::Utf16)?;
    Ok((s, &[]))
}

#[inline]
pub fn read_u32(data: &[u8], off: usize) -> Result<u32, ParseError> {
    let bytes = data.get(off..off + 4).ok_or(ParseError::Bounds)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

pub fn filetime_to_rfc3339(filetime: u64) -> String {
    let seconds = filetime / 10_000_000;
    let nanos = (filetime % 10_000_000) * 100;
    let unix_seconds = (seconds as i64) - 11_644_473_600;
    chrono::DateTime::from_timestamp(unix_seconds, nanos as u32)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

pub fn generate_process_guid(timestamp: u64, pid: u32) -> String {
    let mut hasher = Sha256::new();
    hasher.update(timestamp.to_le_bytes());
    hasher.update(pid.to_le_bytes());
    let hash = hasher.finalize();
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]),
        u16::from_le_bytes([hash[4], hash[5]]),
        u16::from_le_bytes([hash[6], hash[7]]),
        hash[8],
        hash[9],
        hash[10],
        hash[11],
        hash[12],
        hash[13],
        hash[14],
        hash[15]
    )
}

pub fn get_pid_from_tid(tid: u32) -> u32 {
    if tid == 0 {
        return 0;
    }

    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{
            GetProcessIdOfThread, OpenThread, THREAD_QUERY_LIMITED_INFORMATION,
        };

        unsafe {
            if let Ok(handle) = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, false, tid) {
                if !handle.is_invalid() {
                    let pid = GetProcessIdOfThread(handle);
                    let _ = CloseHandle(handle);
                    return pid;
                }
            }
        }
    }
    0
}

pub fn get_process_info_live(pid: u32) -> (String, String) {
    if pid == 0 {
        return (String::new(), String::new());
    }

    #[cfg(windows)]
    {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::ProcessStatus::GetProcessImageFileNameW;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

        unsafe {
            if let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
                if !handle.is_invalid() {
                    let mut buffer = [0u16; 260];
                    let len = GetProcessImageFileNameW(handle, &mut buffer);
                    let _ = CloseHandle(handle);
                    if len > 0 {
                        let path = String::from_utf16_lossy(&buffer[..len as usize]);
                        let normalized = crate::cache::get_cache().normalize_path(&path);
                        let integrity = get_integrity_level(pid);
                        return (normalized, integrity);
                    }
                }
            }
        }
    }
    (String::new(), String::new())
}

#[cfg(windows)]
fn get_integrity_level(pid: u32) -> String {
    use windows::Win32::Foundation::{CloseHandle, PSID};
    use windows::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenIntegrityLevel,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        if let Ok(proc_handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            if !proc_handle.is_invalid() {
                let mut token_handle = windows::Win32::Foundation::HANDLE::default();
                if OpenProcessToken(proc_handle, TOKEN_QUERY, &mut token_handle).is_ok() {
                    let mut size = 0u32;
                    let _ =
                        GetTokenInformation(token_handle, TokenIntegrityLevel, None, 0, &mut size);
                    if size > 0 {
                        let mut buffer = vec![0u8; size as usize];
                        if GetTokenInformation(
                            token_handle,
                            TokenIntegrityLevel,
                            Some(buffer.as_mut_ptr() as *mut _),
                            size,
                            &mut size,
                        )
                        .is_ok()
                        {
                            let label = buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL;
                            let sid: PSID = (*label).Label.Sid;
                            let count = GetSidSubAuthorityCount(sid);
                            if !count.is_null() && *count > 0 {
                                let rid = *GetSidSubAuthority(sid, (*count as u32) - 1);
                                let _ = CloseHandle(token_handle);
                                let _ = CloseHandle(proc_handle);
                                return match rid {
                                    0x0000 => "Untrusted".to_string(),
                                    0x1000 => "Low".to_string(),
                                    0x2000 => "Medium".to_string(),
                                    0x2100 => "MediumPlus".to_string(),
                                    0x3000 => "High".to_string(),
                                    0x4000 => "System".to_string(),
                                    0x5000 => "Protected".to_string(),
                                    _ => format!("Level{}", rid),
                                };
                            }
                        }
                    }
                    let _ = CloseHandle(token_handle);
                }
                let _ = CloseHandle(proc_handle);
            }
        }
    }
    String::new()
}

#[cfg(not(windows))]
fn get_integrity_level(_pid: u32) -> String {
    String::new()
}
