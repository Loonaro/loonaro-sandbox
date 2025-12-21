//! smart caching for enrichment lookups
//! caches file hashes, sid lookups, drive mappings, and process info

use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::sync::RwLock;
use std::time::SystemTime;

static CACHE: std::sync::OnceLock<EnrichmentCache> = std::sync::OnceLock::new();

pub fn get_cache() -> &'static EnrichmentCache {
    CACHE.get_or_init(EnrichmentCache::new)
}

#[derive(Clone, Default, Debug)]
pub struct FileHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

#[derive(Clone, Default, Debug)]
pub struct CachedProcess {
    pub image: String,
    pub user: String,
}

pub struct EnrichmentCache {
    file_hashes: RwLock<HashMap<FileKey, FileHashes>>,
    sid_users: RwLock<HashMap<Vec<u8>, String>>,
    drive_map: RwLock<HashMap<String, String>>,
    processes: RwLock<HashMap<u32, CachedProcess>>,
}

#[derive(Clone, Hash, Eq, PartialEq)]
struct FileKey {
    path: String,
    size: u64,
    mtime: u64,
}

impl EnrichmentCache {
    pub fn new() -> Self {
        let cache = Self {
            file_hashes: RwLock::new(HashMap::new()),
            sid_users: RwLock::new(HashMap::new()),
            drive_map: RwLock::new(HashMap::new()),
            processes: RwLock::new(HashMap::new()),
        };
        cache.init_drive_map();
        cache
    }

    pub fn get_file_hashes(&self, path: &str) -> Option<FileHashes> {
        let meta = std::fs::metadata(path).ok()?;
        let size = meta.len();
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let key = FileKey {
            path: path.to_string(),
            size,
            mtime,
        };

        if let Ok(cache) = self.file_hashes.read() {
            if let Some(hashes) = cache.get(&key) {
                return Some(hashes.clone());
            }
        }

        let hashes = hash_file(path)?;
        if let Ok(mut cache) = self.file_hashes.write() {
            cache.insert(key, hashes.clone());
        }
        Some(hashes)
    }

    pub fn invalidate_file_path(&self, path: &str) {
        if let Ok(mut cache) = self.file_hashes.write() {
            cache.retain(|key, _| key.path != path);
        }
    }

    pub fn get_user_from_sid(&self, sid_bytes: &[u8]) -> String {
        if let Ok(cache) = self.sid_users.read() {
            if let Some(user) = cache.get(sid_bytes) {
                return user.clone();
            }
        }

        let user = sid_to_user(sid_bytes);
        if !user.is_empty() {
            if let Ok(mut cache) = self.sid_users.write() {
                cache.insert(sid_bytes.to_vec(), user.clone());
            }
        }
        user
    }

    pub fn normalize_path(&self, path: &str) -> String {
        if !path.starts_with("\\Device\\") {
            return path.to_string();
        }

        if let Ok(map) = self.drive_map.read() {
            for (device, drive) in map.iter() {
                if path.starts_with(device) {
                    return path.replacen(device, drive, 1);
                }
            }
        }
        path.to_string()
    }

    pub fn get_process_info(&self, pid: u32) -> Option<CachedProcess> {
        if pid == 0 {
            return None;
        }
        if let Ok(cache) = self.processes.read() {
            return cache.get(&pid).cloned();
        }
        None
    }

    pub fn store_process_info(&self, pid: u32, image: String, user: String) {
        if pid > 0 {
            if let Ok(mut cache) = self.processes.write() {
                cache.insert(pid, CachedProcess { image, user });
            }
        }
    }

    pub fn invalidate_process(&self, pid: u32) {
        if let Ok(mut cache) = self.processes.write() {
            cache.remove(&pid);
        }
    }

    fn init_drive_map(&self) {
        #[cfg(windows)]
        {
            use windows::core::PCWSTR;
            use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

            let mut map = HashMap::new();
            for drive in b'A'..=b'Z' {
                let drive_letter = format!("{}:", drive as char);
                let mut target = [0u16; 260];

                unsafe {
                    let wide: Vec<u16> = drive_letter
                        .encode_utf16()
                        .chain(std::iter::once(0))
                        .collect();
                    let result = QueryDosDeviceW(PCWSTR(wide.as_ptr()), Some(&mut target));
                    if result > 0 {
                        let device = String::from_utf16_lossy(&target[..result as usize])
                            .trim_end_matches('\0')
                            .to_string();
                        if !device.is_empty() {
                            map.insert(device, drive_letter);
                        }
                    }
                }
            }

            if let Ok(mut drive_map) = self.drive_map.write() {
                *drive_map = map;
            }
        }
    }
}

impl Default for EnrichmentCache {
    fn default() -> Self {
        Self::new()
    }
}

fn hash_file(path: &str) -> Option<FileHashes> {
    use md5::Context as Md5Context;

    let file = std::fs::File::open(path).ok()?;
    let mut reader = std::io::BufReader::new(file);
    let mut md5_ctx = Md5Context::new();
    let mut sha1_hasher = Sha1::new();
    let mut sha256_hasher = Sha256::new();
    let mut buffer = [0u8; 32768];

    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                md5_ctx.consume(&buffer[..n]);
                sha1_hasher.update(&buffer[..n]);
                sha256_hasher.update(&buffer[..n]);
            }
            Err(_) => return None,
        }
    }

    Some(FileHashes {
        md5: format!("{:x}", md5_ctx.compute()),
        sha1: hex::encode(sha1_hasher.finalize()),
        sha256: hex::encode(sha256_hasher.finalize()),
    })
}

fn sid_to_user(sid_bytes: &[u8]) -> String {
    #[cfg(windows)]
    {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::PSID;
        use windows::Win32::Security::{LookupAccountSidW, SID_NAME_USE};

        if sid_bytes.len() < 8 {
            return String::new();
        }

        unsafe {
            let sid_ptr = PSID(sid_bytes.as_ptr() as *mut _);
            let mut name_size = 0u32;
            let mut domain_size = 0u32;
            let mut use_type = SID_NAME_USE::default();

            let _ = LookupAccountSidW(
                PCWSTR::null(),
                sid_ptr,
                windows::core::PWSTR::null(),
                &mut name_size,
                windows::core::PWSTR::null(),
                &mut domain_size,
                &mut use_type,
            );

            if name_size == 0 {
                return String::new();
            }

            let mut name_buf = vec![0u16; name_size as usize];
            let mut domain_buf = vec![0u16; domain_size as usize];

            if LookupAccountSidW(
                PCWSTR::null(),
                sid_ptr,
                windows::core::PWSTR(name_buf.as_mut_ptr()),
                &mut name_size,
                windows::core::PWSTR(domain_buf.as_mut_ptr()),
                &mut domain_size,
                &mut use_type,
            )
            .is_ok()
            {
                let domain = String::from_utf16_lossy(&domain_buf[..domain_size as usize]);
                let name = String::from_utf16_lossy(&name_buf[..name_size as usize]);
                if domain.is_empty() {
                    return name;
                }
                return format!("{}\\{}", domain, name);
            }
        }
    }

    #[cfg(not(windows))]
    {}

    String::new()
}
