use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

use super::{AnalysisProvider, ProvisionConfig};
use crate::config::NetworkMode;

pub struct WindowsSandboxProvider {
    agent_bin_path: std::path::PathBuf,
}

impl WindowsSandboxProvider {
    pub fn new(agent_bin_path: std::path::PathBuf) -> Self {
        Self { agent_bin_path }
    }

    fn create_wsb(&self, config: &ProvisionConfig) -> Result<std::path::PathBuf> {
        let networking = match config.network_mode {
            NetworkMode::Block => "Disable",
            NetworkMode::Simulate | NetworkMode::Allow => "Enable",
        };

        let wsb_content = format!(
            r#"<Configuration>
  <VGpu>Enable</VGpu>
  <Networking>{}</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{}</HostFolder>
      <SandboxFolder>C:\Users\WDAGUtilityAccount\Desktop\loonaro\box_config</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -File C:\Users\WDAGUtilityAccount\Desktop\loonaro\box_config\sandbox-startup.ps1</Command>
  </LogonCommand>
</Configuration>"#,
            networking,
            config.session_dir.display()
        );

        let wsb_path = config.session_dir.join("loonaro.wsb");
        std::fs::write(&wsb_path, wsb_content)?;
        Ok(wsb_path)
    }

    fn create_startup_script(&self, config: &ProvisionConfig) -> Result<()> {
        let script = r#"
$ErrorActionPreference = "Stop"
cd C:\Users\WDAGUtilityAccount\Desktop\loonaro\box_config
Start-Sleep -Seconds 2
./agent.exe
"#;
        std::fs::write(config.session_dir.join("sandbox-startup.ps1"), script)?;
        Ok(())
    }

    fn copy_agent(&self, session_dir: &Path) -> Result<()> {
        let dest = session_dir.join("agent.exe");
        std::fs::copy(&self.agent_bin_path, &dest)
            .with_context(|| format!("Failed to copy agent from {:?}", self.agent_bin_path))?;
        Ok(())
    }

    fn copy_sample(&self, config: &ProvisionConfig) -> Result<()> {
        let dest = config.session_dir.join(config.sample_name);
        std::fs::copy(config.sample_path, &dest)?;
        Ok(())
    }
}

impl AnalysisProvider for WindowsSandboxProvider {
    fn name(&self) -> &str {
        "Windows Sandbox"
    }

    fn provision(&self, config: &ProvisionConfig) -> Result<()> {
        self.copy_agent(config.session_dir)?;
        self.copy_sample(config)?;
        self.create_startup_script(config)?;
        let wsb_path = self.create_wsb(config)?;

        println!("Launching Windows Sandbox...");
        Command::new("WindowsSandbox.exe")
            .arg(&wsb_path)
            .spawn()
            .context("Failed to launch Windows Sandbox")?;

        Ok(())
    }
}
