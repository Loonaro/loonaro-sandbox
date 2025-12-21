use std::net::SocketAddr;
use std::path::Path;

// use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Unused
use tokio_rustls::server::TlsStream;

use crate::artifacts::ArtifactCollector;
use crate::processor::collect;
use yara_scanner::{ArtifactScanner, YaraScanSummary};

pub async fn handle_session(
    stream: TlsStream<tokio::net::TcpStream>,
    remote_addr: SocketAddr,
    session_id: &str,
    output_dir: &str,
    moose_url: &str,
    moose_key: &str,
    duration: std::time::Duration,
) {
    let mut collected_events: Vec<loonaro_models::sigma::MalwareEvent> = Vec::with_capacity(1024);
    let output_path = Path::new(output_dir);
    let mut artifact_collector = ArtifactCollector::new(session_id, output_path);

    let mut connection = comms::Connection::new(stream);

    if let Err(e) = collect(
        &mut connection,
        &mut collected_events,
        moose_url,
        moose_key,
        session_id,
        &mut artifact_collector,
        duration,
    )
    .await
    {
        eprintln!("Error handling connection from {}: {}", remote_addr, e);
    }

    finalize_session(session_id, output_dir, &mut artifact_collector).await;
}

async fn finalize_session(
    session_id: &str,
    output_dir: &str,
    artifact_collector: &mut ArtifactCollector,
) {
    println!("Session {} ended. Finalizing...", session_id);

    match artifact_collector.collect_final_versions().await {
        Ok(files) => println!("Collected {} final file versions", files.len()),
        Err(e) => eprintln!("Failed to collect final versions: {}", e),
    }

    if let Err(e) = artifact_collector.save_manifest().await {
        eprintln!("Failed to save artifact manifest: {}", e);
    }

    run_yara_scan(output_dir).await;

    let summary = artifact_collector.summary();
    println!("Artifact Summary: {:?}", summary);
    println!("Session {} complete.", session_id);
}

async fn run_yara_scan(output_dir: &str) {
    let drops_dir = Path::new(output_dir).join("drops");
    if !drops_dir.exists() {
        return;
    }

    let scanner = match ArtifactScanner::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to init YARA scanner: {}", e);
            return;
        }
    };

    match scanner.scan_directory(&drops_dir) {
        Ok(results) => {
            let summary = YaraScanSummary::from_results(&results);
            println!(
                "YARA: {} files, {} matches, severity: {}",
                summary.total_files_scanned, summary.files_with_matches, summary.severity
            );

            let yara_path = Path::new(output_dir).join("yara_results.json");
            if let Ok(json) = serde_json::to_string_pretty(&summary) {
                let _ = tokio::fs::write(&yara_path, json).await;
            }
        }
        Err(e) => eprintln!("YARA scan failed: {}", e),
    }
}
