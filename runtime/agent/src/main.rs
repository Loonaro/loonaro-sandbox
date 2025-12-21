mod commandline;
mod etw_events;
mod injector;
mod memory;
mod pipe_server;

use anyhow::{Context, Result};
use clap::Parser;
use comms::{MemoryDumpHeader, Message, Transport};
use etw::{EtwEvent, EventHeader};
use one_collect::ReadOnly;
use one_collect::etw::AncillaryData;
use one_collect::event::EventData;
use one_collect::helpers::callstack::{CallstackHelp, CallstackHelper};
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, ServerName};
use serde::Deserialize;
use std::cell::RefCell;
use std::mem::MaybeUninit;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::{TlsConnector, client::TlsStream};

const SANDBOX_CONFIG_PATH: &str =
    r"C:\Users\WDAGUtilityAccount\Desktop\loonaro\box_config\agent_config.json";
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

struct TlsClientTransport {
    stream: TlsStream<tokio::net::TcpStream>,
}

impl comms::Transport for TlsClientTransport {
    async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(data).await
    }
    async fn receive(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use tokio::io::AsyncReadExt;
        self.stream.read(buf).await
    }
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
                // We use the same CommonName as generated in Monitor's PKI
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
                        let mut transport = TlsClientTransport { stream: tls_stream };

                        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8192);

                        let transport_handle = tokio::spawn(async move {
                            while let Some(buf) = rx.recv().await {
                                if let Err(e) = transport.send(&buf).await {
                                    eprintln!("comms send error: {e}");
                                    break;
                                }
                            }
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
                                            if let Err(e) = send_memory_dump(
                                                &dump_tx,
                                                pid,
                                                &proc_name,
                                                base_address as u64,
                                                region_size,
                                                "RWX Alloc",
                                            )
                                            .await
                                            {
                                                eprintln!("Failed to send dump: {}", e);
                                            }
                                        }
                                    }
                                    pipe_server::HookEvent::MemoryProtect {
                                        new_protect, ..
                                    } => {
                                        if new_protect == 0x40 || new_protect == 0x80 {
                                            // We don't track size perfectly here
                                        }
                                    }
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
    tx: &mpsc::Sender<Vec<u8>>,
    pid: u32,
    process_name: &str,
    base_address: u64,
    size: usize,
    trigger: &str,
) -> Result<()> {
    if let Ok(reader) = memory::ProcessReader::attach(pid) {
        if let Ok(data) = reader.read_memory(base_address, size) {
            let header = MemoryDumpHeader {
                pid,
                process_name: process_name.to_string(),
                region_base: base_address,
                protection: "RWX".to_string(),
                trigger: trigger.to_string(),
            };

            let header_msg = Message::MemoryDump(header, data.len() as u32);
            let mut buf = Vec::new();
            minicbor::encode(&header_msg, &mut buf)?;
            tx.send(buf).await?;

            tx.send(data).await?;

            println!("Sent memory dump for PID {} ({} bytes)", pid, size);
        }
    }
    Ok(())
}

fn do_etw(tx: mpsc::Sender<Vec<u8>>, duration_seconds: u64) {
    let helper = CallstackHelper::new();
    let mut etw = one_collect::etw::EtwSession::new().with_callstack_help(&helper);

    let ancillary = etw.ancillary_data();
    let counter = Rc::new(RefCell::new(0));

    etw_events::process::register_process(&mut etw, tx.clone(), ancillary.clone(), counter.clone());
    etw_events::file::register_file_create(
        &mut etw,
        tx.clone(),
        ancillary.clone(),
        counter.clone(),
    );
    etw_events::registry::register_registry(
        &mut etw,
        tx.clone(),
        ancillary.clone(),
        counter.clone(),
    );
    etw_events::network::register_network(&mut etw, tx.clone(), ancillary.clone(), counter.clone());
    etw_events::dns::register_dns(&mut etw, tx.clone(), ancillary.clone(), counter.clone());

    let duration = std::time::Duration::from_secs(duration_seconds);

    if let Err(e) = etw.parse_for_duration("agent_process_test", duration) {
        eprintln!("Error during ETW parsing: {}", e);
    }

    let events_sent = counter.take();

    if let Ok(end_buf) = minicbor::to_vec(Message::TracingFinished(events_sent)) {
        let _ = tx.try_send(end_buf);
    }

    println!("Finishing ETW tracing. Events sent: {}", events_sent);
}

fn send_event_enqueue(
    tx: &mpsc::Sender<Vec<u8>>,
    data: &EventData<'_>,
    ancillary: &ReadOnly<AncillaryData>,
    event: EtwEvent,
) -> anyhow::Result<()> {
    let mut header = MaybeUninit::<EventHeader>::uninit();
    ancillary.read(|e| {
        header.write(EventHeader::from_ancillary(e, event));
    });

    // Construct the message as: CBOR(header, payload_size) || payload

    let payload = data.event_data();
    let payload_size = payload.len() as u32; // max 64KB according to ETW docs

    // Try to enqueue without blocking; if failed to send, it's dropped.
    let message = Message::EventHeader(unsafe { header.assume_init() }, payload_size);
    let msg_buf = minicbor::to_vec(message)?;
    match tx.try_send(msg_buf) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Failed to enqueue event message: {}", e);
        }
    }

    match tx.try_send(payload.to_vec()) {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Failed to enqueue event payload: {}", e);
        }
    }

    Ok(())
}
