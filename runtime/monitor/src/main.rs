mod artifacts;
mod config;
mod fakenet_ng;
mod moose;
mod pki;
mod processor;
mod providers;
mod session;

use anyhow::{Context, Result};
use std::sync::Arc;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::{AppConfig, NetworkMode, ProviderType};
use crate::fakenet_ng::FakeNetSession;
use crate::pki::generate_pki;
use crate::providers::windows::WindowsSandboxProvider;
use crate::providers::{AnalysisProvider, ProvisionConfig};
use crate::session::{TlsServerTransport, handle_session};

#[derive(Error, Debug)]
pub enum MonitorError {
    #[error("Failed to parse agent address: {0}")]
    AgentConnectionFailed(#[from] std::net::AddrParseError),

    #[error("Failed to connect to agent: {0}")]
    AgentConnectionError(#[from] tokio::io::Error),

    #[error("TLS Error: {0}")]
    TlsError(#[from] rustls::Error),
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::load();

    let config_dir = std::path::Path::new(&config.output_dir);
    std::fs::create_dir_all(config_dir)?;

    // prescan mode: YARA scan sample and exit
    if config.prescan_only {
        if let Some(sample_path) = &config.sample {
            return run_prescan(sample_path, config_dir).await;
        } else {
            anyhow::bail!("--prescan-only requires --sample");
        }
    }

    let listener = setup_listener(&config).await?;
    let port = listener.local_addr()?.port();
    let host_ip = "127.0.0.1";

    println!("Monitor listening on port {}", port);
    println!("Session ID: {}", config.session_id);

    moose::send_lifecycle(
        &config.moose_url,
        &config.moose_key,
        &config.session_id,
        "RUNNING",
        "Monitor started.",
    )
    .await;

    let pki = generate_pki(host_ip, port, config.duration)?;
    let config_path = config_dir.join("agent_config.json");
    std::fs::write(
        &config_path,
        serde_json::to_string_pretty(&pki.agent_config)?,
    )?;

    if let Some(sample_path) = &config.sample {
        provision_provider(&config, config_dir, sample_path, &config_path)?;
    }

    let acceptor = setup_tls(&pki)?;
    let _fakenet = start_fakenet_if_needed(&config, config_dir);

    accept_connections(listener, acceptor, &config).await
}

async fn run_prescan(sample_path: &std::path::Path, output_dir: &std::path::Path) -> Result<()> {
    use yara_scanner::ArtifactScanner;

    println!("Running YARA prescan on {:?}...", sample_path);

    let scanner = ArtifactScanner::new()?;
    let result = scanner.scan_file(sample_path)?;

    let output_path = output_dir.join("prescan_yara.json");
    let json = serde_json::to_string_pretty(&result)?;
    tokio::fs::write(&output_path, &json).await?;

    println!("Prescan result: {:?}", result);
    println!("Results saved to {:?}", output_path);

    Ok(())
}

fn provision_provider(
    config: &AppConfig,
    session_dir: &std::path::Path,
    sample_path: &std::path::Path,
    agent_config_path: &std::path::Path,
) -> Result<()> {
    let sample_name = sample_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "sample.exe".to_string());

    let agent_bin = config
        .agent_bin
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("agent.exe"));

    let provision_config = ProvisionConfig {
        session_id: &config.session_id,
        session_dir,
        sample_path,
        sample_name: &sample_name,
        network_mode: config.network_mode,
        agent_config_path,
    };

    let provider: Box<dyn AnalysisProvider> = match config.provider {
        ProviderType::Sandbox => Box::new(WindowsSandboxProvider::new(agent_bin)),
    };

    println!("Provisioning {} for analysis...", provider.name());
    provider.provision(&provision_config)?;
    println!("Provider provisioned.");

    Ok(())
}

async fn setup_listener(config: &AppConfig) -> Result<TcpListener> {
    let addr = format!("{}:{}", config.bind_ip, config.bind_port);
    TcpListener::bind(&addr).await.context("Failed to bind")
}

fn setup_tls(pki: &pki::Pki) -> Result<TlsAcceptor> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut pki.agent_config.ca_cert_pem.as_bytes()) {
        roots.add(cert?)?;
    }

    let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("Failed to build client verifier")?;

    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![pki.server_cert.clone()], pki.server_key.clone_key())
        .context("Failed to build server config")?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn start_fakenet_if_needed(
    config: &AppConfig,
    output_dir: &std::path::Path,
) -> Option<FakeNetSession> {
    match config.network_mode {
        NetworkMode::Block => {
            println!("Network mode: BLOCK");
            None
        }
        NetworkMode::Simulate | NetworkMode::Allow => {
            match FakeNetSession::start(
                config.session_id.clone(),
                output_dir.to_path_buf(),
                Some(config.bind_ip),
                config.network_mode,
                &config.simulation_rules,
            ) {
                Ok(session) => {
                    println!(
                        "Network mode: {:?}, PCAP: {:?}",
                        config.network_mode,
                        session.pcap_path()
                    );
                    Some(session)
                }
                Err(e) => {
                    eprintln!("FakeNet-NG failed: {}", e);
                    None
                }
            }
        }
    }
}

async fn accept_connections(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    config: &AppConfig,
) -> Result<()> {
    loop {
        let (socket, remote_addr) = listener.accept().await?;
        println!("Connection from: {}", remote_addr);

        let acceptor = acceptor.clone();
        let session_id = config.session_id.clone();
        let output_dir = config.output_dir.clone();
        let moose_url = config.moose_url.clone();
        let moose_key = config.moose_key.clone();

        tokio::spawn(async move {
            match acceptor.accept(socket).await {
                Ok(stream) => {
                    let mut transport = TlsServerTransport { stream };
                    handle_session(
                        &mut transport,
                        remote_addr,
                        &session_id,
                        &output_dir,
                        &moose_url,
                        &moose_key,
                    )
                    .await;
                }
                Err(e) => eprintln!("TLS error from {}: {}", remote_addr, e),
            }
        });
    }
}
