use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Scanner configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    /// Sources to load YARA rules from
    #[serde(default)]
    pub rule_sources: Vec<RuleSource>,

    /// Scan options
    #[serde(default)]
    pub scan_options: ScanOptions,

    /// Whether to include builtin rules
    #[serde(default = "default_true")]
    pub include_builtin_rules: bool,

    /// External variables to pass to rules
    #[serde(default)]
    pub external_vars: Vec<ExternalVar>,
}

/// Source of YARA rules
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RuleSource {
    /// Load from a directory (all .yar/.yara files)
    Directory(PathBuf),
    /// Load from a single file
    File(PathBuf),
    /// Load from a string
    String { name: String, content: String },
    /// Load from a URL
    Url(String),
    /// Load from compiled rules file
    Compiled(PathBuf),
}

/// What to scan
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ScanTarget {
    /// Scan a file
    File { path: PathBuf },
    /// Scan a directory
    Directory { path: PathBuf, recursive: bool },
    /// Scan a memory buffer
    Buffer { identifier: String },
    /// Scan a process memory
    Process { pid: u32 },
}

/// Scan options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    /// Timeout in seconds (0 = no timeout)
    #[serde(default = "default_timeout")]
    pub timeout_secs: u32,

    /// Maximum file size to scan (None = no limit)
    #[serde(default)]
    pub max_file_size: Option<u64>,

    /// Fast mode - stop after first match per rule
    #[serde(default)]
    pub fast_mode: bool,

    /// Include matching strings in results
    #[serde(default = "default_true")]
    pub include_strings: bool,

    /// Skip files that can't be read
    #[serde(default = "default_true")]
    pub skip_errors: bool,

    /// File extensions to scan (empty = all)
    #[serde(default)]
    pub extensions: Vec<String>,

    /// Patterns to exclude
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
}

/// External variable to pass to rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalVar {
    pub name: String,
    pub value: ExternalValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ExternalValue {
    Integer(i64),
    Float(f64),
    String(String),
    Boolean(bool),
}

fn default_timeout() -> u32 {
    60
}
fn default_true() -> bool {
    true
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            rule_sources: Vec::new(),
            scan_options: ScanOptions::default(),
            include_builtin_rules: true,
            external_vars: Vec::new(),
        }
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            timeout_secs: 60,
            max_file_size: Some(100 * 1024 * 1024), // 100MB
            fast_mode: false,
            include_strings: true,
            skip_errors: true,
            extensions: Vec::new(),
            exclude_patterns: Vec::new(),
        }
    }
}
