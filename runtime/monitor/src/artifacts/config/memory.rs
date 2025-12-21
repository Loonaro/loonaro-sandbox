//! Memory collection configuration

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryCollectionConfig {
    pub enabled: bool,
    pub dump_on_exit: bool,
    pub dump_executable: bool,
    pub dump_on_rwx: bool,
    pub dump_injected: bool,
    pub min_region_size: u64,
    pub max_region_size: u64,
    pub max_per_process_mb: u64,
    pub always_dump_processes: Vec<String>,
    pub never_dump_processes: Vec<String>,
    pub dump_triggers: Vec<MemoryDumpTrigger>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDumpTrigger {
    pub name: String,
    pub api: String,
    pub condition: String,
    pub enabled: bool,
}

impl Default for MemoryCollectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dump_on_exit: true,
            dump_executable: true,
            dump_on_rwx: true,
            dump_injected: true,
            min_region_size: 4096,
            max_region_size: 100 * 1024 * 1024,
            max_per_process_mb: 500,
            always_dump_processes: vec![],
            never_dump_processes: vec![
                "csrss.exe".into(),
                "smss.exe".into(),
                "services.exe".into(),
            ],
            dump_triggers: vec![
                MemoryDumpTrigger {
                    name: "Post-Decrypt".into(),
                    api: "CryptDecrypt".into(),
                    condition: "after".into(),
                    enabled: true,
                },
                MemoryDumpTrigger {
                    name: "RWX-Alloc".into(),
                    api: "VirtualAlloc".into(),
                    condition: "on_rwx".into(),
                    enabled: true,
                },
            ],
        }
    }
}

impl MemoryCollectionConfig {}
