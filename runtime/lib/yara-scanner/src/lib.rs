mod artifacts;
mod config;
mod results;
mod rules;
mod scanner;

pub use artifacts::{ArtifactScanner, YaraMatchDetail, YaraScanSummary};
pub use config::{RuleSource, ScanTarget, ScannerConfig};
pub use results::{Match, MatchMeta, ScanResult, Severity, StringMatch};
pub use rules::{CompiledRules, RuleManager};
pub use scanner::YaraScanner;

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use tracing::info;

/// Re-export ScanOptions from config, not yara_x
pub use config::ScanOptions;

/// High-level YARA scanner with rule management
pub struct Scanner {
    config: ScannerConfig,
    rule_manager: Arc<RuleManager>,
}

impl Scanner {
    /// Create a new scanner with config
    pub fn new(config: ScannerConfig) -> Result<Self> {
        let rule_manager = Arc::new(RuleManager::new(&config)?);
        info!(
            "YARA Scanner initialized with {} rule sources",
            config.rule_sources.len()
        );
        Ok(Self {
            config,
            rule_manager,
        })
    }

    /// Create with default config
    pub fn default_scanner() -> Result<Self> {
        Self::new(ScannerConfig::default())
    }

    /// Scan a file
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<ScanResult> {
        let scanner = YaraScanner::new(self.rule_manager.clone());
        scanner.scan_file(path, &self.config.scan_options)
    }

    /// Scan a memory buffer
    pub fn scan_buffer(&self, data: &[u8], identifier: &str) -> Result<ScanResult> {
        let scanner = YaraScanner::new(self.rule_manager.clone());
        scanner.scan_buffer(data, identifier, &self.config.scan_options)
    }

    /// Scan a directory recursively
    pub fn scan_directory<P: AsRef<Path>>(&self, path: P) -> Result<Vec<ScanResult>> {
        let scanner = YaraScanner::new(self.rule_manager.clone());
        scanner.scan_directory(path, &self.config.scan_options)
    }

    /// Reload rules from sources
    pub fn reload_rules(&mut self) -> Result<()> {
        self.rule_manager = Arc::new(RuleManager::new(&self.config)?);
        info!("YARA rules reloaded");
        Ok(())
    }

    /// Add a rule source dynamically
    pub fn add_rule_source(&mut self, source: RuleSource) -> Result<()> {
        self.config.rule_sources.push(source);
        self.reload_rules()
    }

    /// Get rule manager for advanced operations
    pub fn rule_manager(&self) -> &RuleManager {
        &self.rule_manager
    }
}

/// Builder for Scanner with fluent API
pub struct ScannerBuilder {
    config: ScannerConfig,
}

impl ScannerBuilder {
    pub fn new() -> Self {
        Self {
            config: ScannerConfig::default(),
        }
    }

    /// Add rules from a directory
    pub fn rules_dir<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.config
            .rule_sources
            .push(RuleSource::Directory(path.as_ref().to_path_buf()));
        self
    }

    /// Add rules from a file
    pub fn rules_file<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.config
            .rule_sources
            .push(RuleSource::File(path.as_ref().to_path_buf()));
        self
    }

    /// Add rules from a string
    pub fn rules_string(mut self, name: &str, content: &str) -> Self {
        self.config.rule_sources.push(RuleSource::String {
            name: name.to_string(),
            content: content.to_string(),
        });
        self
    }

    /// Add rules from a URL (fetched at build time)
    pub fn rules_url(mut self, url: &str) -> Self {
        self.config
            .rule_sources
            .push(RuleSource::Url(url.to_string()));
        self
    }

    /// Set scan timeout in seconds
    pub fn timeout(mut self, seconds: u32) -> Self {
        self.config.scan_options.timeout_secs = seconds;
        self
    }

    /// Set max file size to scan
    pub fn max_file_size(mut self, bytes: u64) -> Self {
        self.config.scan_options.max_file_size = Some(bytes);
        self
    }

    /// Enable fast scan mode
    pub fn fast_mode(mut self, enabled: bool) -> Self {
        self.config.scan_options.fast_mode = enabled;
        self
    }

    /// Include string matches in results
    pub fn include_strings(mut self, enabled: bool) -> Self {
        self.config.scan_options.include_strings = enabled;
        self
    }

    /// Build the scanner
    pub fn build(self) -> Result<Scanner> {
        Scanner::new(self.config)
    }
}

impl Default for ScannerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// Common YARA rules for malware detection
pub mod builtin_rules {
    /// Basic PE file detection
    pub const PE_DETECTION: &str = r#"
rule IsPE {
    meta:
        description = "Detects PE files"
        category = "filetype"
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}
"#;

    /// Suspicious strings commonly found in malware
    pub const SUSPICIOUS_STRINGS: &str = r#"
rule SuspiciousStrings {
    meta:
        description = "Detects suspicious strings"
        category = "suspicious"
        severity = "medium"
    strings:
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "powershell" nocase
        $cmd3 = "wscript" nocase
        $cmd4 = "cscript" nocase
        $net1 = "WinHttpRequest" nocase
        $net2 = "XMLHTTP" nocase
        $net3 = "urlmon" nocase
        $reg1 = "CurrentVersion\\Run" nocase
        $reg2 = "CurrentVersion\\RunOnce" nocase
        $crypt1 = "CryptDecrypt" nocase
        $crypt2 = "VirtualAlloc" nocase
        $crypt3 = "WriteProcessMemory" nocase
    condition:
        3 of them
}
"#;

    /// Packed/obfuscated code detection
    pub const PACKER_DETECTION: &str = r#"
rule PackedOrObfuscated {
    meta:
        description = "Detects packed or obfuscated code"
        category = "packer"
        severity = "high"
    strings:
        $upx = "UPX!" ascii
        $mpress = "MPRESS" ascii
        $aspack = ".aspack" ascii
        $pecompact = "PEC2" ascii
        $themida = ".themida" ascii
        $vmprotect = ".vmp0" ascii
    condition:
        any of them
}
"#;

    /// Shellcode patterns
    pub const SHELLCODE_PATTERNS: &str = r#"
rule ShellcodePatterns {
    meta:
        description = "Detects common shellcode patterns"
        category = "shellcode"
        severity = "critical"
    strings:
        $kernel32_hash = { 64 A1 30 00 00 00 }
        $get_eip = { E8 00 00 00 00 (58|59|5A|5B|5C|5D|5E|5F) }
    condition:
        any of them
}
"#;

    /// Ransomware indicators
    pub const RANSOMWARE_INDICATORS: &str = r#"
rule RansomwareIndicators {
    meta:
        description = "Detects ransomware indicators"
        category = "ransomware"
        severity = "critical"
    strings:
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".crypted" nocase
        $note1 = "your files have been encrypted" nocase
        $note2 = "bitcoin" nocase
        $note3 = "decrypt" nocase
        $note4 = "ransom" nocase
        $api1 = "CryptEncrypt"
        $api2 = "CryptGenKey"
        $shadow = "vssadmin" nocase
    condition:
        (2 of ($ext*) or 2 of ($note*)) and (any of ($api*) or $shadow)
}
"#;

    /// All builtin rules combined
    pub fn all() -> String {
        format!(
            "{}\n{}\n{}\n{}\n{}",
            PE_DETECTION,
            SUSPICIOUS_STRINGS,
            PACKER_DETECTION,
            SHELLCODE_PATTERNS,
            RANSOMWARE_INDICATORS
        )
    }
}
