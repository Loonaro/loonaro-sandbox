//! Artifact types

use serde::{Deserialize, Serialize};

/// Tracked artifact types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Artifact {
    DroppedFile {
        path: String,
        collected_path: Option<String>, // Where we saved it
        size: u64,
        sha256: Option<String>,
        created_by_pid: Option<u32>,
        collected: bool,
        event: FileEvent,  // create, modify, delete
        version: u32,      // Version number if same file modified multiple times
        timestamp: String, // When we captured it
    },
    MemoryDump {
        pid: u32,
        process_name: String,
        base_address: u64,
        size: u64,
        protection: String,
        dump_path: std::path::PathBuf,
        trigger: String,
        timestamp: String,
    },
    RegistryKey {
        key: String,
        value_name: Option<String>,
        value_data: Option<String>,
        action: String,
        pid: Option<u32>,
        timestamp: String,
    },
    NetworkIOC {
        ioc_type: String,
        value: String,
        protocol: String,
        port: Option<u16>,
        pid: Option<u32>,
        timestamp: String,
    },
    Other {
        name: String,
        path: String,
        size: u64,
        timestamp: String,
    },
}

/// File event type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileEvent {
    Create,
    Modify,
    Delete,
    Rename { old_path: String },
}

/// Collection statistics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CollectionStats {
    pub files_tracked: usize,
    pub files_collected: usize,
    pub files_skipped_by_config: usize,
    pub files_skipped_too_large: usize,
    pub files_not_found: usize,
    pub memory_dumps: usize,
    pub memory_dumps_skipped: usize,
    pub network_iocs: usize,
    pub network_iocs_skipped: usize,
    pub registry_keys: usize,
    pub registry_keys_skipped: usize,
    pub bytes_collected: u64,
}

/// Summary of collected artifacts for reporting
#[derive(Debug, Serialize)]
pub struct ArtifactSummary {
    pub session_id: String,
    pub dropped_files_count: usize,
    pub memory_dumps_count: usize,
    pub registry_changes_count: usize,
    pub network_iocs_count: usize,
    pub total_artifacts: usize,
    pub total_bytes_collected: u64,
    pub stats: CollectionStats,
}
