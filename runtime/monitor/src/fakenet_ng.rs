use anyhow::{Context, Result};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use crate::config::{NetworkMode, SimulationRule};

const FAKENET_DEFAULT_PATH: &str = "tools/fakenet-ng/fakenet.exe";

pub struct FakeNetSession {
    child: Child,
    pcap_path: PathBuf,
}

impl FakeNetSession {
    pub fn start(
        session_id: String,
        output_dir: PathBuf,
        sandbox_ip: Option<IpAddr>,
        network_mode: NetworkMode,
        simulation_rules: &Vec<SimulationRule>,
    ) -> Result<Self> {
        let pcap_path = output_dir.join(format!("{}.pcap", session_id));
        let ini_path = output_dir.join("fakenet.ini");

        write_config(
            &ini_path,
            &pcap_path,
            sandbox_ip,
            network_mode,
            simulation_rules,
        )?;

        let fakenet_exe = std::env::var("FAKENET_PATH").unwrap_or(FAKENET_DEFAULT_PATH.to_string());

        let child = Command::new(&fakenet_exe)
            .args(["-c", ini_path.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to start FakeNet-NG from {}", fakenet_exe))?;

        println!(
            "FakeNet-NG started (PID: {:?}) for session {}",
            child.id(),
            session_id
        );
        if let Some(ip) = sandbox_ip {
            println!("  filtering traffic from: {}", ip);
        }

        Ok(Self { child, pcap_path })
    }

    pub fn pcap_path(&self) -> &Path {
        &self.pcap_path
    }
}

impl Drop for FakeNetSession {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
        println!("FakeNet-NG stopped. PCAP: {:?}", self.pcap_path);
    }
}

fn write_config(
    config_path: &Path,
    pcap_path: &Path,
    sandbox_ip: Option<IpAddr>,
    network_mode: NetworkMode,
    simulation_rules: &Vec<SimulationRule>,
) -> Result<()> {
    // filter to sandbox ip if known
    let host_filter = match sandbox_ip {
        Some(ip) => format!("HostBlackList: !{}", ip),
        None => String::new(),
    };

    // in allow mode, we just capture but dont intercept (passthrough)
    let divert_traffic = match network_mode {
        NetworkMode::Simulate => "Yes",
        NetworkMode::Allow => "No", // just capture
        NetworkMode::Block => "No", // shouldnt get here but safe default
    };

    // generate custom listener sections from simulation rules
    let custom_listeners = generate_custom_listeners(simulation_rules);

    let config = format!(
        r#"[FakeNet]
DivertTraffic: {}
DumpPackets: Yes
PacketFile: {}
DebugLevel: 0

[Diverter]
NetworkMode: SingleHost
DefaultTCPListener: ProxyListener
DefaultUDPListener: DNSListener
{}

[DNSListener]
Enabled: True
Port: 53
ResponseIP: 192.0.2.1

[HTTPListener]
Enabled: True
Port: 80
DumpHTTPPosts: Yes

[HTTPListener443]
Enabled: True
Port: 443
UseSSL: Yes

[ProxyListener]
Enabled: True
Protocol: TCP

{}
"#,
        divert_traffic,
        pcap_path.display(),
        host_filter,
        custom_listeners
    );

    std::fs::write(config_path, config).context("failed to write fakenet config")?;
    Ok(())
}

// generate fakenet listener sections for custom simulation rules
fn generate_custom_listeners(rules: &[SimulationRule]) -> String {
    let mut sections = String::new();
    for (i, rule) in rules.iter().enumerate() {
        let section = format!(
            r#"[CustomListener_{}]
Enabled: True
Port: {}
Protocol: {}
{}
"#,
            i,
            rule.port,
            rule.protocol.to_uppercase(),
            rule.response_base64
                .as_ref()
                .map(|r| format!("Response: {}", r))
                .unwrap_or_default()
        );
        sections.push_str(&section);
        sections.push('\n');
    }
    sections
}
