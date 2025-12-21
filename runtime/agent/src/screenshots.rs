use anyhow::Result;
use loonaro_models::sigma::{agent_message, AgentMessage, ArtifactUpload};
use screenshots::Screen;
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;

pub async fn run(tx: Sender<AgentMessage>) -> Result<()> {
    // Loop interval
    let interval = Duration::from_secs(2);

    loop {
        match capture_screenshot() {
            Ok(data) => {
                if !data.is_empty() {
                    let total_size = data.len() as u64;
                    let artifact = ArtifactUpload {
                        session_id: "".to_string(),
                        file_path: "screenshot.jpg".to_string(), // TODO: Timestamp?
                        offset: 0,
                        r#type: "screenshot".to_string(),
                        total_size,
                        data,
                        is_last_chunk: true,
                    };

                    let msg = AgentMessage {
                        payload: Some(agent_message::Payload::Artifact(artifact)),
                    };

                    if let Err(e) = tx.send(msg).await {
                        eprintln!("Failed to send screenshot: {}", e);
                        break;
                    }
                }
            }
            Err(e) => {
                eprintln!("Screenshot error: {}", e);
            }
        }
        sleep(interval).await;
    }
    Ok(())
}

fn capture_screenshot() -> Result<Vec<u8>> {
    let screens = Screen::all();
    if let Some(screen) = screens.first() {
        if let Some(image) = screen.capture() {
            let width = image.width();
            let height = image.height();
            let pixels = image.buffer();
            if let Some(img_buf) = image::RgbaImage::from_raw(width, height, pixels.clone()) {
                let mut buffer = Vec::new();
                img_buf.write_to(
                    &mut std::io::Cursor::new(&mut buffer),
                    image::ImageOutputFormat::Jpeg(70),
                )?;
                return Ok(buffer);
            }
        }
    }
    Ok(Vec::new())
}
