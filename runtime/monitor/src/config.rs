use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, path::PathBuf};

// how to handle network traffic from the sandbox
#[derive(Debug, Clone, Copy, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    // sandbox network disabled, no traffic
    #[default]
    Block,
    // fakenet-ng intercepts and fakes responses
    Simulate,
    // real network (dangerous, use with caution)
    Allow,
}

// custom response rule for fakenet simulation mode
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationRule {
    // port to intercept
    pub port: u16,
    // tcp, udp, http, dns
    pub protocol: String,
    // base64 encoded response payload
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_base64: Option<String>,
}

// which vm/sandbox provider to use
#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum ProviderType {
    #[default]
    Sandbox, // windows sandbox (ephemeral)
}
/// Loonaro Monitor CLI
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    // Artifacts output directory
    #[arg(long, default_value = "../box_config")]
    output_dir: String,

    // Unique job id
    #[arg(long, default_value = "unknown-session")]
    session_id: String,

    // Listen port - 0 = dynamic
    #[arg(long, default_value_t = 0)]
    port: u16,

    // Listen ip - 0.0.0.0 = all interfaces
    #[arg(long, default_value = "0.0.0.0")]
    ip: IpAddr,

    // Moose ingest endpoint
    #[arg(long)]
    moose_url: Option<String>,

    // Moose API key
    #[arg(long)]
    moose_key: Option<String>,

    // Analysis timeout in seconds
    #[arg(long, default_value_t = 60)]
    duration: u64,

    /// Network mode
    /// block: sandbox network disabled, no traffic
    /// simulate: fakenet-ng intercepts and fakes responses
    /// allow: real network (dangerous, use with caution)
    #[arg(long, value_enum, default_value_t = NetworkMode::Block)]
    network_mode: NetworkMode,

    /// Sandbox provider
    #[arg(long, value_enum, default_value_t = ProviderType::Sandbox)]
    provider: ProviderType,

    /// Malware sample to run
    #[arg(long)]
    sample: Option<PathBuf>,

    /// Path to agent.exe
    #[arg(long)]
    agent_bin: Option<PathBuf>,

    /// Custom fakenet rules in json format
    /// example: [{"port": 80, "protocol": "tcp", "response_base64": ""}]
    #[arg(long)]
    simulation_rules: Option<String>,

    /// Just yara scan then exit (no execution or sandboxing)
    #[arg(long, default_value_t = false)]
    prescan_only: bool,
}

// runtime config parsed from cli + env
pub struct AppConfig {
    pub output_dir: String,                    // where to dump artifacts
    pub session_id: String,                    // unique job id
    pub bind_port: u16,                        // 0 = dynamic
    pub bind_ip: IpAddr,                       // listen addr
    pub moose_url: String,                     // moose ingest endpoint
    pub moose_key: String,                     // moose api key
    pub duration: u64,                         // analysis timeout secs
    pub network_mode: NetworkMode,             // block/simulate/allow
    pub provider: ProviderType,                // sandbox provider
    pub sample: Option<PathBuf>,               // malware sample to run
    pub agent_bin: Option<PathBuf>,            // path to agent.exe
    pub simulation_rules: Vec<SimulationRule>, // custom fakenet rules
    pub prescan_only: bool,                    // just yara scan then exit
}

impl AppConfig {
    pub fn load() -> Self {
        let cli = Cli::parse();

        let moose_url = cli
            .moose_url
            .or_else(|| std::env::var("MOOSE_URL").ok())
            .unwrap_or_else(|| "http://localhost:4000".to_string());

        let moose_key = cli
            .moose_key
            .or_else(|| std::env::var("MOOSE_KEY").ok())
            .unwrap_or_else(|| "moose_secret".to_string());

        let simulation_rules: Vec<SimulationRule> = cli
            .simulation_rules
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        Self {
            output_dir: cli.output_dir,
            session_id: cli.session_id,
            bind_port: cli.port,
            bind_ip: cli.ip,
            moose_url,
            moose_key,
            duration: cli.duration,
            network_mode: cli.network_mode,
            provider: cli.provider,
            sample: cli.sample,
            agent_bin: cli.agent_bin,
            simulation_rules,
            prescan_only: cli.prescan_only,
        }
    }
}
