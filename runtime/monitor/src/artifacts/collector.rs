//! Artifact collector implementation

use super::config::ArtifactConfig;
use super::types::{Artifact, ArtifactSummary, CollectionStats, FileEvent};
use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info, warn};

/// Artifact collector with configurable rules
pub struct ArtifactCollector {
    session_id: String,
    output_dir: PathBuf,
    config: ArtifactConfig,
    /// Tracks file versions: path -> version count
    file_versions: HashMap<String, u32>,
    artifacts: Vec<Artifact>,
    total_collected_bytes: u64,
    stats: CollectionStats,
}

impl ArtifactCollector {
    pub fn new(session_id: &str, output_dir: &Path) -> Self {
        Self::with_config(session_id, output_dir, ArtifactConfig::default())
    }

    pub fn with_config(session_id: &str, output_dir: &Path, config: ArtifactConfig) -> Self {
        info!("ArtifactCollector initialized for session {}", session_id);
        Self {
            session_id: session_id.to_string(),
            output_dir: output_dir.to_path_buf(),
            config,
            file_versions: HashMap::new(),
            artifacts: Vec::new(),
            total_collected_bytes: 0,
            stats: CollectionStats::default(),
        }
    }

    #[inline]
    fn timestamp() -> String {
        Utc::now().to_rfc3339()
    }

    /// Track file creation (sync, just track - use track_and_collect_file for immediate)
    pub fn track_file_create(&mut self, path: &str, pid: Option<u32>) {
        self.stats.files_tracked += 1;

        if !self.config.files.should_collect(path, 0) {
            debug!("Skipping file by config: {}", path);
            self.stats.files_skipped_by_config += 1;
            return;
        }

        let version = self.file_versions.entry(path.to_string()).or_insert(0);
        *version += 1;

        self.artifacts.push(Artifact::DroppedFile {
            path: path.to_string(),
            collected_path: None,
            size: 0,
            sha256: None,
            created_by_pid: pid,
            collected: false,
            event: FileEvent::Create,
            version: *version,
            timestamp: Self::timestamp(),
        });
    }

    // track_and_collect_file removed

    /// Track registry change
    pub fn track_registry_change(
        &mut self,
        key: &str,
        value_name: Option<&str>,
        value_data: Option<&str>,
        action: &str,
        pid: Option<u32>,
    ) {
        self.stats.registry_keys += 1;

        if !self.config.registry.should_track(key) {
            self.stats.registry_keys_skipped += 1;
            return;
        }

        self.artifacts.push(Artifact::RegistryKey {
            key: key.to_string(),
            value_name: value_name.map(|s| s.to_string()),
            value_data: value_data.map(|s| s.to_string()),
            action: action.to_string(),
            pid,
            timestamp: Self::timestamp(),
        });
    }

    /// Track network IOC
    pub fn track_network_ioc(
        &mut self,
        ioc_type: &str,
        value: &str,
        protocol: &str,
        port: Option<u16>,
        pid: Option<u32>,
    ) {
        self.stats.network_iocs += 1;

        if ioc_type == "domain" && !self.config.network.should_track_dns(value) {
            self.stats.network_iocs_skipped += 1;
            return;
        }

        if ioc_type == "ip" {
            let dest_port = port.unwrap_or(0);
            if !self
                .config
                .network
                .should_track_connection(value, dest_port, protocol)
            {
                self.stats.network_iocs_skipped += 1;
                return;
            }
        }

        self.artifacts.push(Artifact::NetworkIOC {
            ioc_type: ioc_type.to_string(),
            value: value.to_string(),
            protocol: protocol.to_string(),
            port,
            pid,
            timestamp: Self::timestamp(),
        });
    }

    /// Save memory dump immediately

    pub async fn save_artifact_chunk(
        &mut self,
        artifact: &loonaro_models::sigma::ArtifactUpload,
    ) -> Result<()> {
        let max_bytes = self.config.settings.max_total_size_mb * 1024 * 1024;
        if self.total_collected_bytes + artifact.data.len() as u64 > max_bytes {
            warn!("Skipping artifact chunk - max size reached");
            return Err(anyhow::anyhow!("Max size reached"));
        }

        let sub_dir = if artifact.r#type == "MEMORY_DUMP" {
            "memory"
        } else {
            "uploads"
        };
        let dir = self.output_dir.join(sub_dir);
        if !dir.exists() {
            fs::create_dir_all(&dir).await?;
        }

        let safe_name = artifact
            .file_path
            .replace(|c: char| !c.is_alphanumeric() && c != '.', "_");
        let file_path = dir.join(&safe_name);

        use tokio::io::AsyncWriteExt;
        let mut file = if artifact.offset == 0 {
            fs::File::create(&file_path).await?
        } else {
            fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(&file_path)
                .await?
        };

        file.write_all(&artifact.data).await?;

        self.total_collected_bytes += artifact.data.len() as u64;
        self.stats.bytes_collected += artifact.data.len() as u64;

        if artifact.is_last_chunk {
            info!("Saved artifact fully: {:?}", file_path);
            let size = fs::metadata(&file_path).await?.len();

            // Map artifact type to enum if possible, or use Generic/Other
            // For now simple mapping:
            if artifact.r#type == "MEMORY_DUMP" {
                self.stats.memory_dumps += 1;
                // We don't have all details like base_address here easily unless encoded in filename or artifact metadata
                // For now, simpler tracking:
                self.artifacts.push(Artifact::MemoryDump {
                    pid: 0, // Unknown
                    process_name: "unknown".to_string(),
                    base_address: 0,
                    size,
                    protection: "unknown".to_string(),
                    dump_path: file_path,
                    trigger: "agent_upload".to_string(),
                    timestamp: Self::timestamp(),
                });
            } else {
                self.artifacts.push(Artifact::Other {
                    name: artifact.file_path.clone(),
                    path: file_path.to_string_lossy().to_string(),
                    size,
                    timestamp: Self::timestamp(),
                });
            }
        }
        Ok(())
    }

    pub async fn collect_final_versions(&mut self) -> Result<Vec<PathBuf>> {
        let drops_dir = self.output_dir.join("drops");
        fs::create_dir_all(&drops_dir).await?;

        let mut collected = Vec::new();
        let tracked: Vec<String> = self.file_versions.keys().cloned().collect();

        for file_path in tracked {
            let source = Path::new(&file_path);
            if !source.exists() {
                continue;
            }

            let _metadata = match fs::metadata(&source).await {
                Ok(m) => m,
                Err(_) => continue,
            };

            // Get version
            let version = self.file_versions.get(&file_path).copied().unwrap_or(0) + 1;
            self.file_versions.insert(file_path.clone(), version);

            let base_name = source
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "final".to_string());

            let dest_name = format!("{}_v{}_final", base_name, version);
            let dest = drops_dir.join(&dest_name);

            if let Ok(bytes) = fs::copy(&source, &dest).await {
                collected.push(dest.clone());
                self.total_collected_bytes += bytes;

                let sha256 = if self.config.settings.hash_all_artifacts {
                    if let Ok(data) = fs::read(&dest).await {
                        use sha2::{Digest, Sha256};
                        Some(hex::encode(Sha256::digest(&data)))
                    } else {
                        None
                    }
                } else {
                    None
                };

                self.artifacts.push(Artifact::DroppedFile {
                    path: file_path,
                    collected_path: Some(dest.to_string_lossy().to_string()),
                    size: bytes,
                    sha256,
                    created_by_pid: None,
                    collected: true,
                    event: FileEvent::Modify, // Final is effectively the last modify
                    version,
                    timestamp: Self::timestamp(),
                });
            }
        }

        info!("Collected {} final file versions", collected.len());
        Ok(collected)
    }

    // Getters removed

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(&self.artifacts)?)
    }

    pub async fn save_manifest(&self) -> Result<PathBuf> {
        let manifest_path = self.output_dir.join("artifacts.json");
        fs::write(&manifest_path, self.to_json()?).await?;

        let stats_path = self.output_dir.join("collection_stats.json");
        fs::write(&stats_path, serde_json::to_string_pretty(&self.stats)?).await?;

        let config_path = self.output_dir.join("artifact_config.json");
        self.config.to_file(&config_path)?;

        info!("Saved manifest to {:?}", self.output_dir);
        Ok(manifest_path)
    }

    pub fn summary(&self) -> ArtifactSummary {
        ArtifactSummary {
            session_id: self.session_id.clone(),
            dropped_files_count: self
                .artifacts
                .iter()
                .filter(|a| matches!(a, Artifact::DroppedFile { .. }))
                .count(),
            memory_dumps_count: self
                .artifacts
                .iter()
                .filter(|a| matches!(a, Artifact::MemoryDump { .. }))
                .count(),
            registry_changes_count: self
                .artifacts
                .iter()
                .filter(|a| matches!(a, Artifact::RegistryKey { .. }))
                .count(),
            network_iocs_count: self
                .artifacts
                .iter()
                .filter(|a| matches!(a, Artifact::NetworkIOC { .. }))
                .count(),
            total_artifacts: self.artifacts.len(),
            total_bytes_collected: self.total_collected_bytes,
            stats: self.stats.clone(),
        }
    }
}
