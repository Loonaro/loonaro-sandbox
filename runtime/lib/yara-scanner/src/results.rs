use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Result of scanning a single target
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Unique scan ID
    pub id: String,

    /// Target identifier (file path, buffer name, etc.)
    pub target: String,

    /// Type of target (file, buffer, process)
    pub target_type: String,

    /// Size of scanned data in bytes
    pub size: u64,

    /// SHA256 hash of the data
    pub sha256: Option<String>,

    /// List of matching rules
    pub matches: Vec<Match>,

    /// Time taken to scan in milliseconds
    pub scan_time_ms: u64,

    /// Timestamp of scan
    pub timestamp: DateTime<Utc>,

    /// Error message if scan failed
    pub error: Option<String>,

    /// Whether the scan was skipped
    pub skipped: bool,
}

/// A single YARA rule match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Match {
    /// Rule name
    pub rule: String,

    /// Rule namespace
    pub namespace: String,

    /// Rule tags
    pub tags: Vec<String>,

    /// Rule metadata
    pub meta: Vec<MatchMeta>,

    /// Matching strings
    pub strings: Vec<StringMatch>,
}

/// Rule metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchMeta {
    pub key: String,
    pub value: String,
}

/// A matching string
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringMatch {
    /// String identifier
    pub identifier: String,

    /// Offset in data
    pub offset: u64,

    /// Matched data (truncated)
    pub data: Option<String>,
}

impl ScanResult {
    /// Check if any rules matched
    pub fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }

    /// Get severity based on matched rules
    pub fn severity(&self) -> Severity {
        if self.matches.iter().any(|m| {
            m.meta
                .iter()
                .any(|meta| meta.key == "severity" && meta.value.contains("critical"))
        }) {
            return Severity::Critical;
        }

        if self.matches.iter().any(|m| {
            m.meta
                .iter()
                .any(|meta| meta.key == "severity" && meta.value.contains("high"))
        }) {
            return Severity::High;
        }

        if self.matches.iter().any(|m| {
            m.meta
                .iter()
                .any(|meta| meta.key == "severity" && meta.value.contains("medium"))
        }) {
            return Severity::Medium;
        }

        if self.has_matches() {
            Severity::Low
        } else {
            Severity::None
        }
    }

    /// Get all matched rule names
    pub fn matched_rules(&self) -> Vec<&str> {
        self.matches.iter().map(|m| m.rule.as_str()).collect()
    }

    /// Get all tags from matched rules
    pub fn all_tags(&self) -> Vec<&str> {
        self.matches
            .iter()
            .flat_map(|m| m.tags.iter().map(String::as_str))
            .collect()
    }

    /// Create a skipped result
    pub fn skipped(target: String, reason: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            target,
            target_type: "unknown".to_string(),
            size: 0,
            sha256: None,
            matches: Vec::new(),
            scan_time_ms: 0,
            timestamp: Utc::now(),
            error: Some(reason),
            skipped: true,
        }
    }

    /// Create an error result
    pub fn error(target: String, error: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            target,
            target_type: "unknown".to_string(),
            size: 0,
            sha256: None,
            matches: Vec::new(),
            scan_time_ms: 0,
            timestamp: Utc::now(),
            error: Some(error),
            skipped: false,
        }
    }
}

impl Match {
    /// Get a specific metadata value
    pub fn get_meta(&self, key: &str) -> Option<&str> {
        self.meta
            .iter()
            .find(|m| m.key == key)
            .map(|m| m.value.as_str())
    }

    /// Get category from metadata
    pub fn category(&self) -> Option<&str> {
        self.get_meta("category")
    }

    /// Get description from metadata
    pub fn description(&self) -> Option<&str> {
        self.get_meta("description")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::None => write!(f, "none"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}
