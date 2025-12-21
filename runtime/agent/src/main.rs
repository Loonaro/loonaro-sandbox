mod cache;
mod commandline;
mod etw_events;
mod injector;
mod memory;
mod pipe_server;
mod screenshots;
mod utils;

use anyhow::{Context, Result};
use clap::Parser;
use loonaro_models::sigma::{agent_message, monitor_message, AgentMessage, MonitorMessage};
use comms::Connection;
use one_collect::helpers::callstack::{CallstackHelp, CallstackHelper};
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, ServerName};
use serde::Deserialize;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;

// Alias connection type
type AgentConnection<S> = Connection<S, MonitorMessage, AgentMessage>;

#[cfg(target_os = "windows")]
const SANDBOX_CONFIG_PATH: &str =
    r"C:\Users\WDAGUtilityAccount\Desktop\loonaro\box_config\agent_config.json";
#[cfg(target_os = "windows")]
const DEV_CONFIG_REL_PATH: &str = r"..\box_config\agent_config.json";

const CONNECT_RETRY_INTERVAL_SECONDS: u64 = 5;

#[derive(Deserialize, Debug, Clone)]
struct AgentConfig {
    monitor_ip: String,
    monitor_port: u16,
    ca_cert_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
    pub duration_seconds: u64,
}

fn find_config() -> Result<AgentConfig> {
    let possible_paths = vec![
        PathBuf::from(SANDBOX_CONFIG_PATH),
        PathBuf::from(DEV_CONFIG_REL_PATH),
    ];

    for path in possible_paths {
        if path.exists() {
            println!("Found config at: {:?}", path);
            let content = std::fs::read_to_string(&path)?;
            let config: AgentConfig = serde_json::from_str(&content)?;
            return Ok(config);
        }
    }

    anyhow::bail!("Could not find agent_config.json in any of the search paths.");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = commandline::Cli::parse();

    let (hook_tx, mut hook_rx) = mpsc::channel(100);

    tokio::spawn(async {
        if let Err(e) = pipe_server::run_server(hook_tx).await {
            eprintln!("Pipe server error: {}", e);
        }
    });

    if let Some(commandline::Commands::Run { path, dll }) = &args.command {
        println!("Launching target: {} with DLL: {}", path, dll);
        unsafe {
            if let Err(e) = injector::spawn_and_inject(path, dll) {
                eprintln!("Failed to inject: {}", e);
            }
        }
    }

    let config = find_config().context("Failed to load agent configuration")?;

    println!(
        "Loaded configuration for Monitor at {}:{}",
        config.monitor_ip, config.monitor_port
    );

    let mut root_store = rustls::RootCertStore::empty();

    for cert in rustls_pemfile::certs(&mut config.ca_cert_pem.as_bytes()) {
        root_store.add(cert?)?;
    }

    let client_certs: Vec<CertificateDer> =
        rustls_pemfile::certs(&mut config.client_cert_pem.as_bytes()).collect::<Result<_, _>>()?;

    let client_key = rustls_pemfile::private_key(&mut config.client_key_pem.as_bytes())?
        .ok_or_else(|| anyhow::anyhow!("No private key found in config"))?;

    let tls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(client_certs, client_key)?;

    let connector = TlsConnector::from(Arc::new(tls_config));
    let remote_addr = format!("{}:{}", config.monitor_ip, config.monitor_port);

    println!("Connecting to Monitor at {}", remote_addr);

    loop {
        match TcpStream::connect(&remote_addr).await {
            Ok(stream) => {
                let domain = match ServerName::try_from("loonaro-monitor") {
                    Ok(d) => d,
                    Err(_) => {
                        eprintln!("Invalid server name configuration");
                        return Ok(());
                    }
                };
                match connector.connect(domain, stream).await {
                    Ok(tls_stream) => {
                        println!("Connected securely!");
                        let connection = AgentConnection::new(tls_stream);
                        let (mut writer, mut reader) = connection.split();

                        let (tx, mut rx) = mpsc::channel::<AgentMessage>(8192);

                        // sender task
                        let transport_handle = tokio::spawn(async move {
                            while let Some(msg) = rx.recv().await {
                                if let Err(e) = writer.send(msg).await {
                                    eprintln!("comms send error: {e}");
                                    break;
                                }
                            }
                        });

                        let screenshot_tx = tx.clone();
                        tokio::spawn(async move {
                            if let Err(e) = screenshots::run(screenshot_tx).await {
                                eprintln!("Screenshot task died: {}", e);
                            }
                        });

                        // receiver task
                        let stop_tx = tx.clone();
                        tokio::spawn(async move {
                            while let Some(result) = reader.recv().await {
                                match result {
                                    Ok(msg) => match msg.payload {
                                        Some(monitor_message::Payload::Command(cmd)) => {
                                            println!("Received Command: {:?}", cmd.action);
                                            // Handle StopTracing
                                            if cmd.action == loonaro_models::sigma::command::Action::StopTracing as i32 {
                                                 println!("Stopping requested. Flushing and exiting.");
                                                 // Send CommandAck
                                                 let ack = loonaro_models::sigma::CommandAck {
                                                     action: cmd.action,
                                                     success: true,
                                                     session_id: "".to_string(),
                                                 };
                                                 let msg = AgentMessage {
                                                     payload: Some(agent_message::Payload::CommandAck(ack)),
                                                 };
                                                 let _ = stop_tx.send(msg).await;
                                                 
                                                 tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                                                 std::process::exit(0);
                                            }
                                        },
                                        _ => {}
                                    },
                                    Err(e) => {
                                        eprintln!("Codec Error or Connection Closed: {}", e);
                                        break;
                                    }
                                }
                            }
                            eprintln!("Monitor closed connection.");
                            std::process::exit(0);
                        });

                        let dump_tx = tx.clone();
                        let hook_handle = tokio::spawn(async move {
                            while let Some((pid, proc_name, event)) = hook_rx.recv().await {
                                match event {
                                    pipe_server::HookEvent::MemoryAlloc {
                                        base_address,
                                        region_size,
                                        protect,
                                        ..
                                    } => {
                                        if protect == 0x40 || protect == 0x80 {
                                            let _ = send_memory_dump(
                                                &dump_tx,
                                                pid,
                                                &proc_name,
                                                base_address as u64,
                                                region_size,
                                                "RWX Alloc",
                                            )
                                            .await;
                                        }
                                    }
                                    pipe_server::HookEvent::MemoryProtect {
                                        new_protect, ..
                                    } => if new_protect == 0x40 || new_protect == 0x80 {},
                                    _ => {}
                                }
                            }
                        });

                        do_etw(tx, config.duration_seconds);

                        transport_handle.abort();
                        hook_handle.abort();
                        return Ok(());
                    }
                    Err(e) => eprintln!("TLS handshake failed: {}", e),
                }
            }
            Err(e) => eprintln!("Failed to connect: {}. Retrying in 5s...", e),
        }
        tokio::time::sleep(std::time::Duration::from_secs(
            CONNECT_RETRY_INTERVAL_SECONDS,
        ))
        .await;
    }
}

async fn send_memory_dump(
    tx: &mpsc::Sender<AgentMessage>,
    pid: u32,
    process_name: &str,
    base_address: u64,
    size: usize,
    _trigger: &str,
) -> Result<()> {
    if let Ok(reader) = memory::ProcessReader::attach(pid) {
        if let Ok(data) = reader.read_memory(base_address, size) {
            // Using ArtifactUpload for Memory Dump
            let file_name = format!("{}_{}_{:#x}.dmp", pid, process_name, base_address);
            
            let total_size = data.len() as u64; 
            let artifact = loonaro_models::sigma::ArtifactUpload {
                session_id: "".to_string(),
                file_path: file_name,
                offset: 0,
                r#type: "MEMORY_DUMP".to_string(),
                total_size,
                data,
                is_last_chunk: true,
            };

            let msg = AgentMessage {
                payload: Some(agent_message::Payload::Artifact(artifact)),
            };
            tx.send(msg).await.context("Failed to send memory dump")?;

            println!("Sent memory dump for PID {} ({} bytes)", pid, size);
        }
    }
    Ok(())
}

fn do_etw(tx: mpsc::Sender<AgentMessage>, duration_seconds: u64) {
    let helper = CallstackHelper::new();
    let mut etw = one_collect::etw::EtwSession::new().with_callstack_help(&helper);

    let ancillary = etw.ancillary_data();
    let counter = Rc::new(RefCell::new(0));

    etw_events::process::register_process(&mut etw, tx.clone(), ancillary.clone(), counter.clone());
    etw_events::file::register_file(&mut etw, tx.clone(), ancillary.clone(), counter.clone());
    etw_events::registry::register_registry(&mut etw, tx.clone(), ancillary.clone(), counter.clone());
    etw_events::network::register_network(&mut etw, tx.clone(), ancillary.clone(), counter.clone());
    etw_events::dns::register_dns_client(&mut etw, tx.clone(), ancillary.clone(), counter.clone());
    etw_events::thread::register_thread_events(&mut etw, tx.clone(), ancillary.clone(), counter.clone());
    etw_events::image_load::register_image_load(&mut etw, tx.clone(), ancillary.clone(), counter.clone());
    etw_events::pipe::register_pipe_events(&mut etw, tx.clone(), ancillary.clone(), counter.clone());
    etw_events::wmi::register_wmi_events(&mut etw, tx.clone(), ancillary.clone(), counter.clone());
    etw_events::powershell::register_powershell_events(&mut etw, tx.clone(), ancillary.clone(), counter.clone());
    etw_events::handle::register_handle_events(&mut etw, tx.clone(), ancillary.clone(), counter.clone());
    etw_events::ldap::register_ldap_events(&mut etw, tx.clone(), ancillary.clone(), counter.clone());
    etw_events::pnp::register_pnp_events(&mut etw, tx.clone(), ancillary.clone(), counter.clone());

    let duration = std::time::Duration::from_secs(duration_seconds);

    if let Err(e) = etw.parse_for_duration("agent_process_test", duration) {
        eprintln!("Error during ETW parsing: {}", e);
    }

    let events_sent = counter.take();
    println!("Finishing ETW tracing loop. Events sent: {}", events_sent);
}
