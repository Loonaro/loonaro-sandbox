use crate::artifacts::ArtifactCollector;
use crate::moose::{send_lifecycle, send_malware_event};
use anyhow::Result;
use comms::Connection;
use loonaro_models::sigma::{AgentMessage, MalwareEvent, MonitorMessage, agent_message};
use tokio::io::{AsyncRead, AsyncWrite};

// We need to alias the Connection type since it's generic now
type MonitorConnection<S> = Connection<S, AgentMessage, MonitorMessage>;

pub async fn collect(
    connection: &mut MonitorConnection<impl AsyncRead + AsyncWrite + Unpin>,
    all_events: &mut Vec<MalwareEvent>,
    moose_url: &str,
    moose_key: &str,
    session_id: &str,
    artifact_collector: &mut ArtifactCollector,
    duration: std::time::Duration,
) -> Result<()> {
    let sleep = tokio::time::sleep(duration);
    tokio::pin!(sleep);
    let mut stop_command_sent = false;

    loop {
        tokio::select! {
            _ = &mut sleep => {
                 if !stop_command_sent {
                     println!("Time limit reached. Sending Stop command to agent...");

                     // Construct MonitorMessage with Command
                     let cmd = loonaro_models::sigma::Command {
                         action: loonaro_models::sigma::command::Action::StopTracing.into(),
                         reason: "Timeout".to_string(),
                     };

                     let msg = MonitorMessage {
                         payload: Some(loonaro_models::sigma::monitor_message::Payload::Command(cmd)),
                     };
                     connection.send(msg).await?;

                     stop_command_sent = true;
                     sleep.as_mut().reset(tokio::time::Instant::now() + std::time::Duration::from_secs(10));
                 } else {
                     println!("Agent did not disconnect in time. Force closing.");
                     return Ok(());
                 }
            }
            res = connection.recv() => {
                match res {
                    Some(Ok(msg)) => {
                        handle_message(
                            msg,
                            all_events,
                            moose_url,
                            moose_key,
                            session_id,
                            artifact_collector
                        ).await?;
                    }
                    Some(Err(e)) => {
                        return Err(anyhow::anyhow!("Connection error: {}", e));
                    }
                    None => { // eof
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn handle_message(
    message: AgentMessage,
    all_events: &mut Vec<MalwareEvent>,
    moose_url: &str,
    moose_key: &str,
    session_id: &str,
    artifact_collector: &mut ArtifactCollector,
) -> Result<()> {
    let payload = match message.payload {
        Some(p) => p,
        None => return Ok(()), // Empty message?
    };

    match payload {
        agent_message::Payload::Event(event) => {
            send_malware_event(moose_url, moose_key, &event).await;

            extract_iocs(&event, artifact_collector);

            all_events.push(event);
            Ok(())
        }
        agent_message::Payload::Heartbeat(hb) => {
            println!(
                "Received Heartbeat: uptime={}s CPU={}%, RAM={} bytes",
                hb.uptime_seconds, hb.cpu_usage_percent, hb.memory_usage_bytes
            );
            Ok(())
        }
        agent_message::Payload::Artifact(artifact) => {
            println!(
                "Received Artifact: {} ({} bytes, offset {})",
                artifact.file_path,
                artifact.data.len(),
                artifact.offset
            );
            if let Err(e) = artifact_collector.save_artifact_chunk(&artifact).await {
                eprintln!("Failed to save artifact chunk: {}", e);
            }
            Ok(())
        }
        agent_message::Payload::CommandAck(ack) => {
            println!(
                "Received CommandAck: {:?} Success={}",
                ack.action, ack.success
            );
            if ack.action == loonaro_models::sigma::command::Action::StopTracing as i32 {
                println!("Agent finished tracing. Events: {}", all_events.len());
                send_lifecycle(
                    moose_url,
                    moose_key,
                    session_id,
                    "COMPLETED",
                    &format!("Tracing finished. Events: {}", all_events.len()),
                )
                .await;
            }
            Ok(())
        }
    }
}

fn extract_iocs(event: &MalwareEvent, collector: &mut ArtifactCollector) {
    // Helper to pull basic details for the local report summary.
    // Ideally Moose handles this, but we keep local tracking for "artifacts.json".

    if let Some(inner) = &event.event {
        match inner {
            loonaro_models::sigma::malware_event::Event::Process(_) => {}
            loonaro_models::sigma::malware_event::Event::File(f) => {
                if f.action == "CREATE" {
                    collector.track_file_create(&f.target_filename, None);
                }
            }
            loonaro_models::sigma::malware_event::Event::Network(n) => {
                if n.protocol == "TCP" || n.protocol == "HTTP" {
                    collector.track_network_ioc(
                        "ip",
                        &n.destination_ip,
                        &n.protocol,
                        Some(n.destination_port as u16),
                        None,
                    );
                } else if n.protocol == "DNS" {
                    collector.track_network_ioc("domain", &n.query_name, "dns", None, None);
                }
            }
            loonaro_models::sigma::malware_event::Event::Registry(r) => {
                collector.track_registry_change(&r.target_object, None, None, &r.action, None);
            }
        }
    }
}
