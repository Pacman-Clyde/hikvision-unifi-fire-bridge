//! Periodic Protect-path probe.
//!
//! Without this, a broken webhook path (DNS, routing, expired certificate,
//! firewall change) is only discovered during an actual fire. The probe
//! verifies DNS resolution, TCP reachability, and TLS certificate validity
//! against the Protect host on an interval, and feeds `/readyz`.
//!
//! Limitation (documented): a plain GET cannot verify the API key or webhook
//! ID without triggering the alarm, so those are only fully validated by a
//! real delivery. The probe still catches the overwhelmingly common failure
//! modes (network, DNS, TLS, host down).

use std::time::Duration;

use reqwest::{Client, Url};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::health::Health;

pub struct ProbeConfig {
    pub url: Url,
    pub interval: Duration,
    pub timeout: Duration,
}

pub async fn run(client: Client, cfg: ProbeConfig, health: Health, cancel: CancellationToken) {
    let mut ticker = tokio::time::interval(cfg.interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = ticker.tick() => {}
        }
        let result = probe_once(&client, &cfg).await;
        match &result {
            Ok(()) => debug!("Protect probe ok"),
            Err(e) => warn!(error = %e, "Protect probe failed"),
        }
        health.probe_result(result).await;
    }
}

/// One probe: any HTTP response over a validated connection counts as
/// reachable — Protect may well return 4xx to an unauthenticated GET of `/`,
/// which still proves DNS + route + TLS.
async fn probe_once(client: &Client, cfg: &ProbeConfig) -> Result<(), String> {
    let request = client.get(cfg.url.clone()).send();
    match timeout(cfg.timeout, request).await {
        Ok(Ok(_response)) => Ok(()),
        Ok(Err(e)) => Err(format!("Protect probe failed: {}", e.without_url())),
        Err(_) => Err(format!(
            "Protect probe timed out after {}s",
            cfg.timeout.as_secs_f32()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn cfg_for(url: Url) -> ProbeConfig {
        ProbeConfig {
            url,
            interval: Duration::from_millis(50),
            timeout: Duration::from_secs(2),
        }
    }

    #[tokio::test]
    async fn any_http_response_counts_as_reachable() {
        // A server that always returns 404: still proves the path works.
        let app = axum::Router::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let url = Url::parse(&format!("http://{addr}/")).unwrap();
        let cfg = cfg_for(url).await;
        assert!(probe_once(&Client::new(), &cfg).await.is_ok());
    }

    #[tokio::test]
    async fn refused_connection_is_a_probe_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let url = Url::parse(&format!("http://{addr}/")).unwrap();
        let cfg = cfg_for(url).await;
        assert!(probe_once(&Client::new(), &cfg).await.is_err());
    }

    #[tokio::test]
    async fn probe_loop_updates_health_and_stops_on_cancel() {
        let app = axum::Router::new();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let health = Health::new(true);
        let cancel = CancellationToken::new();
        let url = Url::parse(&format!("http://{addr}/")).unwrap();
        let handle = tokio::spawn(run(
            Client::new(),
            cfg_for(url).await,
            health.clone(),
            cancel.clone(),
        ));

        // Wait for the first probe result to land.
        let mut ok = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if health.snapshot().await.probe_ok {
                ok = true;
                break;
            }
        }
        assert!(ok, "probe never reported success");
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("probe loop must stop on cancel")
            .unwrap();
    }
}
