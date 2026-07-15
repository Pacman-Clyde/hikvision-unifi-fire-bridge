//! Shared health state, counters, and the HTTP health/readiness server.
//!
//! Readiness (`/readyz`) is deliberately strict for a fire-safety bridge:
//! - the camera stream must be connected;
//! - the periodic Protect probe (when enabled) must be passing;
//! - the most recent real alert delivery must not have failed. A failed
//!   delivery *latches* unreadiness until a later delivery succeeds — a
//!   missed alarm needs a human, not a self-clearing status.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Default, Clone, Serialize)]
pub struct HealthSnapshot {
    pub version: &'static str,
    pub started_unix: u64,
    // Camera path.
    pub camera_connected: bool,
    pub camera_last_message_unix: Option<u64>,
    pub camera_error: Option<String>,
    pub camera_reconnects: u64,
    pub malformed_frames: u64,
    /// Camera events lost before the state machine saw them (queue full).
    /// Dangerous — a fire edge could be among them. Alarm on this.
    pub camera_events_dropped: u64,
    /// Decided alerts lost between state machine and delivery worker.
    /// Recoverable via re-alerting, but still a delivery failure.
    pub alerts_dropped: u64,
    /// Unique `eventType` values seen that did not match FIRE_EVENT_TYPES
    /// (capped list). If your camera's fire type is missing from the
    /// configuration, it shows up here instead of vanishing silently.
    pub unmatched_event_types: Vec<String>,
    // Alerting.
    pub alerts_sent: u64,
    pub last_alert_unix: Option<u64>,
    // Protect delivery path.
    /// False until the first successful real delivery: the probe cannot
    /// validate the webhook ID or API key without triggering the alarm.
    pub webhook_verified: bool,
    pub webhook_successes: u64,
    pub webhook_last_success_unix: Option<u64>,
    pub webhook_failures: u64,
    pub webhook_error: Option<String>,
    // Protect reachability probe.
    pub probe_enabled: bool,
    pub probe_ok: bool,
    pub probe_last_success_unix: Option<u64>,
    pub probe_error: Option<String>,
}

impl HealthSnapshot {
    pub fn ready(&self) -> bool {
        let probe_healthy = !self.probe_enabled || self.probe_ok;
        self.camera_connected && probe_healthy && self.webhook_error.is_none()
    }
}

#[derive(Clone)]
pub struct Health {
    inner: Arc<RwLock<HealthSnapshot>>,
}

impl Health {
    pub fn new(probe_enabled: bool) -> Self {
        let snapshot = HealthSnapshot {
            version: env!("CARGO_PKG_VERSION"),
            started_unix: unix_now(),
            probe_enabled,
            // Until the first probe result arrives, the path is unverified;
            // readiness must not report healthy on startup optimism.
            probe_ok: false,
            ..HealthSnapshot::default()
        };
        Self {
            inner: Arc::new(RwLock::new(snapshot)),
        }
    }

    pub async fn snapshot(&self) -> HealthSnapshot {
        self.inner.read().await.clone()
    }

    pub async fn camera_connected(&self) {
        let mut s = self.inner.write().await;
        s.camera_connected = true;
        s.camera_error = None;
    }

    pub async fn camera_disconnected(&self, error: Option<String>) {
        let mut s = self.inner.write().await;
        s.camera_connected = false;
        s.camera_reconnects += 1;
        if let Some(e) = error {
            s.camera_error = Some(e);
        }
    }

    pub async fn camera_message(&self) {
        self.inner.write().await.camera_last_message_unix = Some(unix_now());
    }

    pub async fn malformed_frame(&self) {
        self.inner.write().await.malformed_frames += 1;
    }

    pub async fn camera_event_dropped(&self) {
        self.inner.write().await.camera_events_dropped += 1;
    }

    pub async fn alert_dropped(&self) {
        self.inner.write().await.alerts_dropped += 1;
    }

    /// Record an event type that did not match the fire matcher. Returns
    /// `true` when the type is new (first sighting — worth a WARN log).
    pub async fn unmatched_event_type(&self, event_type: &str) -> bool {
        const MAX_TRACKED: usize = 32;
        let mut s = self.inner.write().await;
        if s.unmatched_event_types.iter().any(|t| t == event_type) {
            return false;
        }
        if s.unmatched_event_types.len() < MAX_TRACKED {
            s.unmatched_event_types.push(event_type.to_owned());
            true
        } else {
            false
        }
    }

    pub async fn alert_sent(&self) {
        let mut s = self.inner.write().await;
        s.alerts_sent += 1;
        s.last_alert_unix = Some(unix_now());
    }

    pub async fn webhook_success(&self) {
        let mut s = self.inner.write().await;
        s.webhook_verified = true;
        s.webhook_successes += 1;
        s.webhook_last_success_unix = Some(unix_now());
        s.webhook_error = None;
    }

    pub async fn webhook_failure(&self, error: String) {
        let mut s = self.inner.write().await;
        s.webhook_failures += 1;
        s.webhook_error = Some(error);
    }

    pub async fn probe_result(&self, result: Result<(), String>) {
        let mut s = self.inner.write().await;
        match result {
            Ok(()) => {
                s.probe_ok = true;
                s.probe_last_success_unix = Some(unix_now());
                s.probe_error = None;
            }
            Err(e) => {
                s.probe_ok = false;
                s.probe_error = Some(e);
            }
        }
    }
}

pub async fn serve(bind: SocketAddr, health: Health, cancel: CancellationToken) -> Result<()> {
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readiness))
        .route("/status", get(status))
        .with_state(health);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(cancel.cancelled_owned())
        .await?;
    Ok(())
}

/// Minimal readiness body; the full snapshot stays on `/status` so a
/// monitoring-only network sees no more than it needs.
#[derive(Serialize)]
struct ReadyBody {
    ready: bool,
}

async fn readiness(State(health): State<Health>) -> impl IntoResponse {
    let ready = health.snapshot().await.ready();
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(ReadyBody { ready }))
}

async fn status(State(health): State<Health>) -> Json<HealthSnapshot> {
    Json(health.snapshot().await)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_with_probe() -> HealthSnapshot {
        HealthSnapshot {
            camera_connected: true,
            probe_enabled: true,
            probe_ok: true,
            ..HealthSnapshot::default()
        }
    }

    #[test]
    fn ready_requires_camera_and_probe() {
        assert!(healthy_with_probe().ready());
        assert!(
            !HealthSnapshot {
                camera_connected: false,
                ..healthy_with_probe()
            }
            .ready()
        );
        assert!(
            !HealthSnapshot {
                probe_ok: false,
                ..healthy_with_probe()
            }
            .ready()
        );
    }

    #[test]
    fn probe_disabled_does_not_block_readiness() {
        let s = HealthSnapshot {
            camera_connected: true,
            probe_enabled: false,
            probe_ok: false,
            ..HealthSnapshot::default()
        };
        assert!(s.ready());
    }

    #[test]
    fn startup_is_unready_until_first_probe_success() {
        let health = Health::new(true);
        let s = futures_blocking(health.snapshot());
        assert!(
            !s.ready(),
            "must not report ready before the path is verified"
        );
    }

    #[test]
    fn failed_delivery_latches_unready_until_a_success() {
        let health = Health::new(false);
        futures_blocking(async {
            health.camera_connected().await;
            health.webhook_failure("delivery failed".into()).await;
            assert!(!health.snapshot().await.ready());
            health.webhook_success().await;
            assert!(health.snapshot().await.ready());
        });
    }

    #[test]
    fn counters_accumulate() {
        let health = Health::new(false);
        futures_blocking(async {
            health.camera_disconnected(Some("boom".into())).await;
            health.camera_disconnected(None).await;
            health.malformed_frame().await;
            health.camera_event_dropped().await;
            health.alert_dropped().await;
            health.alert_sent().await;
            let s = health.snapshot().await;
            assert_eq!(s.camera_reconnects, 2);
            assert_eq!(s.malformed_frames, 1);
            assert_eq!(s.camera_events_dropped, 1);
            assert_eq!(s.alerts_dropped, 1);
            assert_eq!(s.alerts_sent, 1);
            assert_eq!(s.camera_error.as_deref(), Some("boom"));
        });
    }

    #[test]
    fn unmatched_event_types_are_tracked_once_each_and_capped() {
        let health = Health::new(false);
        futures_blocking(async {
            assert!(health.unmatched_event_type("videoloss").await);
            assert!(!health.unmatched_event_type("videoloss").await);
            assert!(health.unmatched_event_type("thermaldetection").await);
            for i in 0..64 {
                health.unmatched_event_type(&format!("type{i}")).await;
            }
            let s = health.snapshot().await;
            assert!(s.unmatched_event_types.len() <= 32, "list must be capped");
            assert!(s.unmatched_event_types.contains(&"videoloss".to_owned()));
        });
    }

    #[test]
    fn webhook_verified_only_after_first_delivery() {
        let health = Health::new(false);
        futures_blocking(async {
            assert!(!health.snapshot().await.webhook_verified);
            health.webhook_failure("boom".into()).await;
            assert!(!health.snapshot().await.webhook_verified);
            health.webhook_success().await;
            assert!(health.snapshot().await.webhook_verified);
        });
    }

    /// Tiny single-future executor so pure state tests need no tokio runtime.
    fn futures_blocking<T>(fut: impl Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(fut)
    }
}
