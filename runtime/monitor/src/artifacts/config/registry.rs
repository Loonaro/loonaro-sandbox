//! Registry collection configuration

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryCollectionConfig {
    pub enabled: bool,
    pub track_creates: bool,
    pub track_modifications: bool,
    pub track_deletes: bool,
    pub always_track_keys: Vec<String>,
    pub ignore_keys: Vec<String>,
}

impl Default for RegistryCollectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            track_creates: true,
            track_modifications: true,
            track_deletes: true,
            always_track_keys: vec![
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce".into(),
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce".into(),
                "HKLM\\SYSTEM\\CurrentControlSet\\Services".into(),
                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule".into(),
                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options".into(),
            ],
            ignore_keys: vec![],
        }
    }
}

impl RegistryCollectionConfig {
    pub fn should_track(&self, key: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let key_upper = key.to_uppercase();
        for ignored in &self.ignore_keys {
            if key_upper.starts_with(&ignored.to_uppercase()) {
                return false;
            }
        }
        for tracked in &self.always_track_keys {
            if key_upper.starts_with(&tracked.to_uppercase()) {
                return true;
            }
        }
        true
    }
}
