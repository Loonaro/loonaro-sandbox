use crate::config::{RuleSource, ScannerConfig};
use anyhow::{Context, Result};
use std::path::Path;
use tracing::{debug, info, warn};
use walkdir::WalkDir;
use yara_x::{Compiler, Rules};

/// Manages YARA rule compilation and storage
pub struct RuleManager {
    rules: Rules,
    rule_count: usize,
}

/// Compiled rules wrapper for thread-safe access
pub struct CompiledRules {
    inner: Rules,
}

impl RuleManager {
    /// Create a new rule manager from config
    pub fn new(config: &ScannerConfig) -> Result<Self> {
        let mut compiler = Compiler::new();
        let mut rule_count = 0;

        // Add builtin rules if enabled
        if config.include_builtin_rules {
            let builtin = crate::builtin_rules::all();
            compiler
                .add_source(builtin.as_str())
                .context("Failed to compile builtin rules")?;
            rule_count += 5; // Number of builtin rules
            debug!("Added builtin YARA rules");
        }

        // Load rules from each source
        for source in &config.rule_sources {
            match source {
                RuleSource::File(path) => {
                    let content = std::fs::read_to_string(path)
                        .with_context(|| format!("Failed to read rule file: {:?}", path))?;
                    compiler
                        .add_source(content.as_str())
                        .with_context(|| format!("Failed to compile rules from: {:?}", path))?;
                    rule_count += count_rules(&content);
                    info!("Loaded YARA rules from file: {:?}", path);
                }
                RuleSource::Directory(path) => {
                    let count = load_rules_from_dir(&mut compiler, path)?;
                    rule_count += count;
                    info!("Loaded {} rules from directory: {:?}", count, path);
                }
                RuleSource::String { name, content } => {
                    compiler
                        .add_source(content.as_str())
                        .with_context(|| format!("Failed to compile rule: {}", name))?;
                    rule_count += count_rules(content);
                    debug!("Loaded inline rule: {}", name);
                }
                RuleSource::Url(url) => {
                    warn!("URL rule source not yet implemented: {}", url);
                }
                RuleSource::Compiled(path) => {
                    warn!("Compiled rules loading not yet implemented: {:?}", path);
                }
            }
        }

        let rules = compiler.build();

        info!("Compiled {} YARA rules successfully", rule_count);

        Ok(Self { rules, rule_count })
    }

    /// Get the compiled rules
    pub fn rules(&self) -> &Rules {
        &self.rules
    }

    /// Get total rule count
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }
}

fn load_rules_from_dir(compiler: &mut Compiler, dir: &Path) -> Result<usize> {
    let mut count = 0;

    for entry in WalkDir::new(dir)
        .follow_links(true)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.is_file() {
            if let Some(ext) = path.extension() {
                let ext = ext.to_string_lossy().to_lowercase();
                if ext == "yar" || ext == "yara" {
                    match std::fs::read_to_string(path) {
                        Ok(content) => match compiler.add_source(content.as_str()) {
                            Ok(_) => {
                                count += count_rules(&content);
                                debug!("Loaded rules from: {:?}", path);
                            }
                            Err(e) => {
                                warn!("Failed to compile {:?}: {}", path, e);
                            }
                        },
                        Err(e) => {
                            warn!("Failed to read {:?}: {}", path, e);
                        }
                    }
                }
            }
        }
    }

    Ok(count)
}

fn count_rules(content: &str) -> usize {
    content
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("rule ") && !trimmed.starts_with("rule_")
        })
        .count()
}

impl CompiledRules {
    pub fn new(rules: Rules) -> Self {
        Self { inner: rules }
    }

    pub fn rules(&self) -> &Rules {
        &self.inner
    }
}
