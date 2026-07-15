//! Long-lived Hikvision ISAPI alert-stream consumer.
//!
//! A supervisor maintains one Digest-authenticated streaming GET at a time,
//! reconnecting with exponential backoff. The backoff resets after a session
//! that stayed healthy, so a camera that closes the stream periodically does
//! not ratchet up to maximum-length reconnect gaps forever.
//!
//! Every session end — clean or not — emits `StreamItem::Reset` so the fire
//! tracker knows `inactive` notifications may have been lost in the gap.

use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use diqwest::{DigestAuthSession, WithDigestAuth};
use futures_util::StreamExt;
use reqwest::Client;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::event::{CameraEvent, parse_event};
use crate::framing::FrameExtractor;
use crate::health::Health;

/// Pending buffer safety limit; a single event document is a few KiB.
const MAX_BUFFER: usize = 1024 * 1024;
/// A session that lived at least this long resets the reconnect backoff.
const HEALTHY_SESSION: Duration = Duration::from_secs(60);
/// How long the stream reader will wait on a full event queue before
/// counting the event as dropped and moving on. The reader must never stall
/// long enough to lose the camera connection.
const SEND_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub enum StreamItem {
    Event(CameraEvent),
    /// The stream ended or reconnected; per-source state must be re-armed.
    Reset,
}

pub async fn supervisor(
    cfg: Config,
    client: Client,
    tx: mpsc::Sender<StreamItem>,
    health: Health,
    cancel: CancellationToken,
) {
    let auth = DigestAuthSession::new(cfg.hik_user.clone(), cfg.hik_pass.clone());
    let mut delay = cfg.reconnect_initial;
    loop {
        if cancel.is_cancelled() {
            return;
        }
        let started = Instant::now();
        let result = session(&cfg, &client, &auth, &tx, &health, &cancel).await;
        // reqwest/diqwest error chains embed the full request URL; redact the
        // camera address before the string reaches logs or /status.
        let error = result
            .as_ref()
            .err()
            .map(|e| redact(&format!("{e:#}"), &cfg));
        health.camera_disconnected(error.clone()).await;
        if cancel.is_cancelled() {
            return;
        }
        // Any gap can swallow an `inactive` notification.
        let _ = tx.send(StreamItem::Reset).await;

        if started.elapsed() >= HEALTHY_SESSION {
            delay = cfg.reconnect_initial;
        }
        match &error {
            Some(e) => {
                warn!(error = %e, delay_s = delay.as_secs(), "camera stream failed; reconnecting")
            }
            None => info!(
                delay_s = delay.as_secs(),
                "camera stream ended; reconnecting"
            ),
        }
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = sleep(delay) => {}
        }
        delay = (delay * 2).min(cfg.reconnect_max);
    }
}

async fn session(
    cfg: &Config,
    client: &Client,
    auth: &DigestAuthSession,
    tx: &mpsc::Sender<StreamItem>,
    health: &Health,
    cancel: &CancellationToken,
) -> Result<()> {
    let response = client
        .get(cfg.hik_url.clone())
        .send_digest_auth(auth)
        .await?;
    let status = response.status();
    if !status.is_success() {
        bail!("camera returned {status}");
    }
    health.camera_connected().await;
    info!("camera alert stream connected");

    let mut stream = response.bytes_stream();
    let mut extractor = FrameExtractor::new(MAX_BUFFER);

    loop {
        let next = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            next = timeout(cfg.stream_idle, stream.next()) => next,
        };
        let chunk = match next {
            Err(_) => bail!(
                "camera stream idle for more than {}s",
                cfg.stream_idle.as_secs()
            ),
            Ok(None) => return Ok(()),
            Ok(Some(Err(e))) => return Err(e.into()),
            Ok(Some(Ok(chunk))) => chunk,
        };
        health.camera_message().await;

        for frame in extractor.push(&chunk)? {
            match parse_event(&frame) {
                Ok(Some(event)) => forward(tx, event, health).await,
                Ok(None) => debug!("XML frame without event fields"),
                Err(e) => {
                    health.malformed_frame().await;
                    warn!(error = %e, "malformed event XML");
                }
            }
        }
    }
}

/// Replace the camera URL and host with placeholders in an error string.
fn redact(message: &str, cfg: &Config) -> String {
    let mut out = message.replace(cfg.hik_url.as_str(), "<camera>");
    if let Some(host) = cfg.hik_url.host_str() {
        out = out.replace(host, "<camera-host>");
    }
    out
}

/// Forward with a bounded wait. Dropping an event is recorded and logged but
/// must never kill the stream: with re-alerting enabled the camera's repeated
/// `active` notifications make delivery self-healing.
async fn forward(tx: &mpsc::Sender<StreamItem>, event: CameraEvent, health: &Health) {
    match timeout(SEND_TIMEOUT, tx.send(StreamItem::Event(event))).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) | Err(_) => {
            health.camera_event_dropped().await;
            warn!("event queue full; dropped a camera event");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::collections::HashMap;

    #[test]
    fn redact_removes_camera_url_and_host_from_errors() {
        let vars: HashMap<String, String> = [
            ("HIKVISION_HOST", "192.0.2.99:8000"),
            ("HIKVISION_USER", "fire-bridge"),
            ("HIKVISION_PASS", "pw"),
            ("PROTECT_BASE_URL", "https://protect.example.com"),
            ("PROTECT_WEBHOOK_ID", "abc"),
            ("PROTECT_API_KEY", "key"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let cfg = Config::from_map(&vars).unwrap();

        let raw = format!(
            "error sending request for url ({}): connection refused",
            cfg.hik_url
        );
        let cleaned = redact(&raw, &cfg);
        assert!(!cleaned.contains("192.0.2.99"), "cleaned={cleaned}");
        assert!(!cleaned.contains("alertStream"), "cleaned={cleaned}");
        assert!(cleaned.contains("connection refused"));
    }
}
