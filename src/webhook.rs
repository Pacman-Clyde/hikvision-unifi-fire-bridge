//! Delivery of alerts to the UniFi Protect Alarm Manager incoming webhook.
//!
//! Policy:
//! - bounded attempts with linear backoff between them;
//! - network errors, timeouts, 408, 429, and 5xx responses are retried;
//! - other 4xx responses are permanent (wrong key, wrong webhook ID) and are
//!   not retried — retrying a 403 three times only delays the failure signal;
//! - error strings never contain the webhook URL (it embeds the webhook ID,
//!   and `/status` exposes these strings to the monitoring network).

use std::time::Duration;

use reqwest::header::HeaderValue;
use reqwest::{Client, StatusCode, Url};
use tokio::time::{sleep, timeout};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub url: Url,
    pub api_key: HeaderValue,
    pub timeout: Duration,
    pub attempts: u32,
}

/// Outcome carried into health state; the `String` is a sanitised message.
pub type DeliveryResult = Result<(), String>;

pub async fn deliver(client: &Client, cfg: &WebhookConfig, reason: &str) -> DeliveryResult {
    let mut last_error = String::new();
    for attempt in 1..=cfg.attempts {
        let request = client
            .post(cfg.url.clone())
            .header("X-API-Key", cfg.api_key.clone())
            .send();
        match timeout(cfg.timeout, request).await {
            Ok(Ok(response)) if response.status().is_success() => {
                info!(reason, attempt, status = %response.status(), "Protect webhook delivered");
                return Ok(());
            }
            Ok(Ok(response)) => {
                let status = response.status();
                last_error = format!("Protect returned {status}");
                if !is_retryable_status(status) {
                    warn!(reason, attempt, %status, "permanent Protect error; not retrying");
                    return Err(last_error);
                }
            }
            Ok(Err(e)) => {
                last_error = format!("Protect request failed: {}", e.without_url());
            }
            Err(_) => {
                last_error = format!(
                    "Protect request timed out after {}s",
                    cfg.timeout.as_secs_f32()
                );
            }
        }
        if attempt < cfg.attempts {
            warn!(reason, attempt, error = %last_error, "Protect delivery attempt failed; retrying");
            sleep(Duration::from_secs(u64::from(attempt))).await;
        }
    }
    Err(last_error)
}

fn is_retryable_status(status: StatusCode) -> bool {
    status.is_server_error()
        || status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use axum::Router;
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::routing::post;

    #[derive(Clone)]
    struct ServerState {
        hits: Arc<AtomicU32>,
        /// Status codes to return, in order; the last repeats.
        script: Arc<Vec<u16>>,
    }

    async fn start_server(script: Vec<u16>) -> (SocketAddr, Arc<AtomicU32>) {
        let hits = Arc::new(AtomicU32::new(0));
        let state = ServerState {
            hits: hits.clone(),
            script: Arc::new(script),
        };
        let app = Router::new()
            .route(
                "/hook",
                post(
                    |State(s): State<ServerState>, headers: HeaderMap| async move {
                        assert_eq!(
                            headers.get("X-API-Key").and_then(|v| v.to_str().ok()),
                            Some("test-key"),
                            "API key header must be present on every attempt"
                        );
                        let n = s.hits.fetch_add(1, Ordering::SeqCst) as usize;
                        let code = *s.script.get(n).unwrap_or(s.script.last().unwrap());
                        StatusCode::from_u16(code).unwrap()
                    },
                ),
            )
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (addr, hits)
    }

    fn cfg(addr: SocketAddr, attempts: u32) -> WebhookConfig {
        WebhookConfig {
            url: Url::parse(&format!("http://{addr}/hook")).unwrap(),
            api_key: HeaderValue::from_static("test-key"),
            timeout: Duration::from_secs(2),
            attempts,
        }
    }

    #[tokio::test]
    async fn first_attempt_success_delivers_once() {
        let (addr, hits) = start_server(vec![200]).await;
        let client = Client::new();
        assert!(deliver(&client, &cfg(addr, 3), "test").await.is_ok());
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn server_error_is_retried_until_success() {
        let (addr, hits) = start_server(vec![500, 503, 200]).await;
        let client = Client::new();
        assert!(deliver(&client, &cfg(addr, 3), "test").await.is_ok());
        assert_eq!(hits.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn permanent_forbidden_is_not_retried() {
        let (addr, hits) = start_server(vec![403]).await;
        let client = Client::new();
        let err = deliver(&client, &cfg(addr, 3), "test").await.unwrap_err();
        assert!(err.contains("403"), "err={err}");
        assert_eq!(hits.load(Ordering::SeqCst), 1, "403 must not be retried");
    }

    #[tokio::test]
    async fn too_many_requests_is_retried() {
        let (addr, hits) = start_server(vec![429, 200]).await;
        let client = Client::new();
        assert!(deliver(&client, &cfg(addr, 3), "test").await.is_ok());
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn exhausted_attempts_report_sanitised_error() {
        let (addr, hits) = start_server(vec![500]).await;
        let client = Client::new();
        let err = deliver(&client, &cfg(addr, 2), "test").await.unwrap_err();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        assert!(err.contains("500"), "err={err}");
        assert!(
            !err.contains("/hook") && !err.contains(&addr.to_string()),
            "error must not leak the webhook URL: {err}"
        );
    }

    #[tokio::test]
    async fn connection_refused_error_is_sanitised() {
        // Bind then drop a listener to get a port that refuses connections.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let client = Client::new();
        let err = deliver(&client, &cfg(addr, 1), "test").await.unwrap_err();
        assert!(
            !err.contains("/hook") && !err.contains(&addr.port().to_string()),
            "error must not leak the webhook URL: {err}"
        );
    }
}
