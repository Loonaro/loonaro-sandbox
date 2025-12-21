use crate::config::ScanOptions;
use crate::results::{Match, MatchMeta, ScanResult, StringMatch};
use crate::rules::RuleManager;
use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, warn};
use walkdir::WalkDir;
use yara_x::Scanner as YaraXScanner;

/// YARA scanner for files and buffers
pub struct YaraScanner {
    rule_manager: Arc<RuleManager>,
}

impl YaraScanner {
    pub fn new(rule_manager: Arc<RuleManager>) -> Self {
        Self { rule_manager }
    }

    /// Scan a file
    pub fn scan_file<P: AsRef<Path>>(&self, path: P, options: &ScanOptions) -> Result<ScanResult> {
        let path = path.as_ref();
        let start = Instant::now();

        // Check file size
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("Failed to get metadata for: {:?}", path))?;

        if let Some(max_size) = options.max_file_size {
            if metadata.len() > max_size {
                return Ok(ScanResult::skipped(
                    path.to_string_lossy().to_string(),
                    format!("File too large: {} bytes", metadata.len()),
                ));
            }
        }

        // Read file
        let data =
            std::fs::read(path).with_context(|| format!("Failed to read file: {:?}", path))?;

        // Calculate hash
        let hash = calculate_sha256(&data);

        // Scan
        let matches = self.scan_data(&data, options)?;
        let scan_time_ms = start.elapsed().as_millis() as u64;

        Ok(ScanResult {
            id: uuid::Uuid::new_v4().to_string(),
            target: path.to_string_lossy().to_string(),
            target_type: "file".to_string(),
            size: data.len() as u64,
            sha256: Some(hash),
            matches,
            scan_time_ms,
            timestamp: chrono::Utc::now(),
            error: None,
            skipped: false,
        })
    }

    /// Scan a memory buffer
    pub fn scan_buffer(
        &self,
        data: &[u8],
        identifier: &str,
        options: &ScanOptions,
    ) -> Result<ScanResult> {
        let start = Instant::now();
        let hash = calculate_sha256(data);
        let matches = self.scan_data(data, options)?;
        let scan_time_ms = start.elapsed().as_millis() as u64;

        Ok(ScanResult {
            id: uuid::Uuid::new_v4().to_string(),
            target: identifier.to_string(),
            target_type: "buffer".to_string(),
            size: data.len() as u64,
            sha256: Some(hash),
            matches,
            scan_time_ms,
            timestamp: chrono::Utc::now(),
            error: None,
            skipped: false,
        })
    }

    /// Scan a directory
    pub fn scan_directory<P: AsRef<Path>>(
        &self,
        path: P,
        options: &ScanOptions,
    ) -> Result<Vec<ScanResult>> {
        let path = path.as_ref();
        let mut results = Vec::new();

        for entry in WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let entry_path = entry.path();
            if !entry_path.is_file() {
                continue;
            }

            // Check extension filter
            if !options.extensions.is_empty() {
                if let Some(ext) = entry_path.extension() {
                    let ext = ext.to_string_lossy().to_lowercase();
                    if !options.extensions.iter().any(|e| e.to_lowercase() == ext) {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            // Check exclude patterns
            let path_str = entry_path.to_string_lossy();
            if options
                .exclude_patterns
                .iter()
                .any(|p| path_str.contains(p))
            {
                continue;
            }

            match self.scan_file(entry_path, options) {
                Ok(result) => results.push(result),
                Err(e) => {
                    if options.skip_errors {
                        warn!("Failed to scan {:?}: {}", entry_path, e);
                        results.push(ScanResult::error(
                            entry_path.to_string_lossy().to_string(),
                            e.to_string(),
                        ));
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        Ok(results)
    }

    fn scan_data(&self, data: &[u8], options: &ScanOptions) -> Result<Vec<Match>> {
        let rules = self.rule_manager.rules();
        let mut scanner = YaraXScanner::new(rules);

        if options.timeout_secs > 0 {
            scanner.set_timeout(std::time::Duration::from_secs(options.timeout_secs as u64));
        }

        let scan_results = scanner.scan(data)?;

        let mut matches = Vec::new();
        for m in scan_results.matching_rules() {
            let meta: Vec<MatchMeta> = m
                .metadata()
                .map(|(key, value)| MatchMeta {
                    key: key.to_string(),
                    value: format!("{:?}", value),
                })
                .collect();

            let strings: Vec<StringMatch> = if options.include_strings {
                m.patterns()
                    .flat_map(|p| {
                        p.matches().map(move |mat| StringMatch {
                            identifier: p.identifier().to_string(),
                            offset: mat.range().start as u64,
                            data: Some(String::from_utf8_lossy(mat.data()).to_string()),
                        })
                    })
                    .take(10) // Limit string matches
                    .collect()
            } else {
                Vec::new()
            };

            matches.push(Match {
                rule: m.identifier().to_string(),
                namespace: m.namespace().to_string(),
                tags: m.tags().map(|t| t.identifier().to_string()).collect(),
                meta,
                strings,
            });

            debug!("Match: {} in namespace {}", m.identifier(), m.namespace());
        }

        Ok(matches)
    }
}

fn calculate_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
