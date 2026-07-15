//! Bridge Hikvision ISAPI fire-detection events into UniFi Protect Alarm
//! Manager incoming webhooks.
//!
//! Task layout (each independent, all cancellation-aware):
//!
//! ```text
//! camera supervisor ──> event processor ──> webhook worker ──> Protect
//!   (stream + frame      (fire state          (retry +
//!    extraction)          machine)             sanitised errors)
//! Protect probe ────────────────────────────────────────┐
//! health server  <── shared health state <──────────────┘
//! ```
//!
//! This crate is a library so the integration tests can drive the complete
//! pipeline against fake camera and Protect servers.

pub mod camera;
pub mod config;
pub mod event;
pub mod framing;
pub mod health;
pub mod probe;
pub mod state;
pub mod webhook;

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use reqwest::Client;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use camera::StreamItem;
use config::Config;
use event::EventState;
use health::Health;
use state::{Alert, FireTracker, TrackerConfig};
use webhook::WebhookConfig;

/// An alert decision on its way to the webhook worker.
#[derive(Debug)]
struct AlarmRequest {
    source: String,
    alert: Alert,
}

/// Run the bridge until `cancel` fires or a critical task exits.
///
/// Returns `Ok(())` on requested shutdown and an error when a critical task
/// stops on its own — the process should exit non-zero so the container
/// runtime restarts it.
pub async fn run(cfg: Config, cancel: CancellationToken) -> Result<()> {
    let health = Health::new(cfg.probe_interval.is_some());

    let hik_client = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .build()
        .context("building camera HTTP client")?;
    let protect_client = Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .build()
        .context("building Protect HTTP client")?;

    let (event_tx, event_rx) = mpsc::channel::<StreamItem>(256);
    let (alarm_tx, alarm_rx) = mpsc::channel::<AlarmRequest>(32);

    let mut tasks: JoinSet<(&'static str, Result<()>)> = JoinSet::new();

    {
        let (cfg, health, cancel) = (cfg.clone(), health.clone(), cancel.clone());
        let client = hik_client;
        tasks.spawn(async move {
            camera::supervisor(cfg, client, event_tx, health, cancel).await;
            ("camera supervisor", Ok(()))
        });
    }
    {
        let (cfg, health, cancel) = (cfg.clone(), health.clone(), cancel.clone());
        tasks.spawn(async move {
            process_events(event_rx, alarm_tx, &cfg, health, cancel).await;
            ("event processor", Ok(()))
        });
    }
    {
        let (health, cancel) = (health.clone(), cancel.clone());
        let webhook_cfg = WebhookConfig {
            url: cfg.webhook_url.clone(),
            api_key: cfg.api_key.clone(),
            timeout: cfg.webhook_timeout,
            attempts: cfg.webhook_attempts,
        };
        let client = protect_client.clone();
        tasks.spawn(async move {
            webhook_worker(alarm_rx, webhook_cfg, client, health, cancel).await;
            ("webhook worker", Ok(()))
        });
    }
    if let Some(interval) = cfg.probe_interval {
        let probe_cfg = probe::ProbeConfig {
            url: cfg.probe_url.clone(),
            interval,
            timeout: cfg.webhook_timeout,
        };
        let (health, cancel) = (health.clone(), cancel.clone());
        tasks.spawn(async move {
            probe::run(protect_client, probe_cfg, health, cancel).await;
            ("Protect probe", Ok(()))
        });
    }
    {
        let (health, cancel) = (health.clone(), cancel.clone());
        let bind = cfg.health_bind;
        tasks.spawn(async move { ("health server", health::serve(bind, health, cancel).await) });
    }

    info!(
        camera = %cfg.hik_url,
        probe = %cfg.probe_url,
        "bridge started"
    );

    let outcome = tokio::select! {
        _ = cancel.cancelled() => Ok(()),
        joined = tasks.join_next() => match joined {
            Some(Ok((name, result))) => {
                bail!("critical task '{name}' exited unexpectedly: {result:?}")
            }
            Some(Err(e)) => bail!("critical task panicked: {e}"),
            None => bail!("all tasks exited unexpectedly"),
        },
    };

    cancel.cancel();
    while tasks.join_next().await.is_some() {}
    info!("bridge stopped");
    outcome
}

/// Apply the fire state machine to the camera event stream.
async fn process_events(
    mut rx: mpsc::Receiver<StreamItem>,
    alarm_tx: mpsc::Sender<AlarmRequest>,
    cfg: &Config,
    health: Health,
    cancel: CancellationToken,
) {
    let mut tracker = FireTracker::new(TrackerConfig {
        cooldown: cfg.cooldown,
        realert: cfg.realert,
        active_ttl: cfg.active_ttl,
    });
    loop {
        let item = tokio::select! {
            _ = cancel.cancelled() => return,
            item = rx.recv() => match item {
                Some(item) => item,
                None => return,
            },
        };
        match item {
            StreamItem::Reset => tracker.on_stream_reset(),
            StreamItem::Event(event) => {
                if !cfg.fire_matcher.matches(&event.event_type) {
                    continue;
                }
                let source = event.channel.unwrap_or_else(|| "default".into());
                match event.state {
                    EventState::Active => {
                        if let Some(alert) = tracker.on_active(&source, Instant::now()) {
                            health.alert_sent().await;
                            info!(%source, ?alert, event_type = %event.event_type, "fire alert raised");
                            let request = AlarmRequest { source, alert };
                            match timeout(Duration::from_secs(2), alarm_tx.send(request)).await {
                                Ok(Ok(())) => {}
                                Ok(Err(_)) | Err(_) => {
                                    // The worker is wedged or the queue is
                                    // full. Do not crash the daemon: repeated
                                    // `active` notifications will re-raise.
                                    health.dropped_event().await;
                                    error!("alarm queue unavailable; alert not enqueued");
                                }
                            }
                        }
                    }
                    EventState::Inactive => tracker.on_inactive(&source),
                    EventState::Unknown(raw) => {
                        warn!(%source, state = %raw, "unknown eventState; ignoring")
                    }
                }
            }
        }
    }
}

/// Deliver queued alerts to Protect, recording outcomes in health state.
async fn webhook_worker(
    mut rx: mpsc::Receiver<AlarmRequest>,
    cfg: WebhookConfig,
    client: Client,
    health: Health,
    cancel: CancellationToken,
) {
    loop {
        let request = tokio::select! {
            _ = cancel.cancelled() => return,
            request = rx.recv() => match request {
                Some(request) => request,
                None => return,
            },
        };
        let reason = format!("{:?} on source {}", request.alert, request.source);
        match webhook::deliver(&client, &cfg, &reason).await {
            Ok(()) => health.webhook_success().await,
            Err(message) => {
                error!(error = %message, "Protect delivery failed after all attempts");
                health.webhook_failure(message).await;
            }
        }
    }
}
