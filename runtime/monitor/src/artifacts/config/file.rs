//! File collection configuration

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileCollectionConfig {
    pub enabled: bool,
    pub collect_all_creates: bool,
    pub collect_modified: bool,
    pub collect_deleted: bool,
    pub max_file_size: u64,
    pub always_collect_extensions: Vec<String>,
    pub never_collect_extensions: Vec<String>,
    pub include_paths: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub watch_directories: Vec<String>,
    pub collect_from_temp: bool,
    pub collect_from_profile: bool,
    pub collect_from_system: bool,
}

impl Default for FileCollectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            collect_all_creates: true,
            collect_modified: true,
            collect_deleted: false,
            max_file_size: 50 * 1024 * 1024,
            always_collect_extensions: vec![
                "exe".into(),
                "dll".into(),
                "sys".into(),
                "ps1".into(),
                "bat".into(),
                "cmd".into(),
                "vbs".into(),
                "js".into(),
                "hta".into(),
                "wsf".into(),
                "scr".into(),
                "pif".into(),
                "jar".into(),
                "msi".into(),
                "msp".into(),
            ],
            never_collect_extensions: vec!["log".into(), "tmp".into(), "etl".into(), "evtx".into()],
            include_paths: vec![],
            exclude_paths: vec![
                "**/Windows/Logs/**".into(),
                "**/Windows/Temp/**/*.tmp".into(),
            ],
            watch_directories: vec!["%TEMP%".into(), "%APPDATA%".into(), "%LOCALAPPDATA%".into()],
            collect_from_temp: true,
            collect_from_profile: true,
            collect_from_system: false,
        }
    }
}

impl FileCollectionConfig {
    pub fn should_collect(&self, path: &str, size: u64) -> bool {
        if !self.enabled {
            return false;
        }
        if size > self.max_file_size {
            return false;
        }

        let path_lower = path.to_lowercase();

        if let Some(ext) = Path::new(path).extension() {
            let ext_str = ext.to_string_lossy().to_lowercase();
            if self
                .never_collect_extensions
                .iter()
                .any(|e| e.to_lowercase() == ext_str)
            {
                return false;
            }
            if self
                .always_collect_extensions
                .iter()
                .any(|e| e.to_lowercase() == ext_str)
            {
                return true;
            }
        }

        for pattern in &self.exclude_paths {
            if Self::matches_pattern(&path_lower, pattern) {
                return false;
            }
        }

        if !self.include_paths.is_empty() {
            for pattern in &self.include_paths {
                if Self::matches_pattern(&path_lower, pattern) {
                    return true;
                }
            }
            return false;
        }

        self.collect_all_creates
    }

    fn matches_pattern(path: &str, pattern: &str) -> bool {
        if pattern == "**/*" {
            return true;
        }
        path.contains(&pattern.replace("**", "").replace("*", ""))
    }
}
