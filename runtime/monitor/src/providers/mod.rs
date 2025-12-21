pub mod windows;

use anyhow::Result;
use std::path::Path;

use crate::config::NetworkMode;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ProvisionConfig<'a> {
    // the analysis session id responsible for this provision
    pub session_id: &'a str,
    // the directory where artifacts for this session are stored
    pub session_dir: &'a Path,
    // path to the malware sample to analyze
    pub sample_path: &'a Path,
    // name of the malware sample
    pub sample_name: &'a str,
    // network mode for this analysis session
    pub network_mode: NetworkMode,
    // where to find the agent config file
    pub agent_config_path: &'a Path,
}

pub trait AnalysisProvider {
    fn name(&self) -> &str;
    fn provision(&self, config: &ProvisionConfig) -> Result<()>;
}
