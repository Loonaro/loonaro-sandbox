use crate::{ScanResult, Scanner, ScannerBuilder, Severity};
use anyhow::Result;
use std::path::Path;
use tracing::info;

const MAX_SCAN_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100MB

/// High-level scanner specifically for malware artifacts (dropped files, memory dumps, etc.)
pub struct ArtifactScanner {
    scanner: Scanner,
}

impl ArtifactScanner {
    /// Create a new artifact scanner with builtin rules and default malware-oriented settings
    pub fn new() -> Result<Self> {
        let scanner = ScannerBuilder::new()
            .timeout(30)
            .max_file_size(MAX_SCAN_FILE_SIZE)
            .include_strings(true)
            .build()?;

        info!("Artifact YARA scanner initialized");
        Ok(Self { scanner })
    }

    /// Scan all files in a directory recursively
    pub fn scan_directory<P: AsRef<Path>>(&self, path: P) -> Result<Vec<ScanResult>> {
        let path = path.as_ref();
        info!("Scanning directory for artifacts: {:?}", path);
        self.scanner.scan_directory(path)
    }

    /// Scan a single file
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<ScanResult> {
        let path = path.as_ref();
        info!("Scanning file: {:?}", path);
        self.scanner.scan_file(path)
    }

    /// Scan a memory buffer
    pub fn scan_buffer(&self, data: &[u8], identifier: &str) -> Result<ScanResult> {
        self.scanner.scan_buffer(data, identifier)
    }
}

/// Serialized summary of YARA scan results for reporting
#[derive(Debug, serde::Serialize)]
pub struct YaraScanSummary {
    pub total_files_scanned: usize,
    pub files_with_matches: usize,
    pub total_matches: usize,
    pub rules_matched: Vec<String>,
    pub severity: String,
    pub details: Vec<YaraMatchDetail>,
}

#[derive(Debug, serde::Serialize)]
pub struct YaraMatchDetail {
    pub file: String,
    pub rules: Vec<String>,
    pub severity: String,
}

impl YaraScanSummary {
    /// Create a summary from a list of scan results
    pub fn from_results(results: &[ScanResult]) -> Self {
        let mut rules_matched = Vec::new();
        let mut details = Vec::new();
        let mut highest_severity = Severity::None;

        for result in results {
            if result.has_matches() {
                let file_rules: Vec<String> = result
                    .matched_rules()
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                rules_matched.extend(file_rules.clone());

                let sev = result.severity();
                if sev > highest_severity {
                    highest_severity = sev;
                }

                details.push(YaraMatchDetail {
                    file: result.target.clone(),
                    rules: file_rules,
                    severity: result.severity().to_string(),
                });
            }
        }

        // Deduplicate rules
        rules_matched.sort();
        rules_matched.dedup();

        Self {
            total_files_scanned: results.len(),
            files_with_matches: results.iter().filter(|r| r.has_matches()).count(),
            total_matches: rules_matched.len(),
            rules_matched,
            severity: highest_severity.to_string(),
            details,
        }
    }
}
