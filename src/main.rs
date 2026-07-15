use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;
use tracing::info;

use hikvision_unifi_fire_bridge::config::Config;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--healthcheck") => healthcheck(),
        Some(other) => anyhow::bail!("unknown argument '{other}' (supported: --healthcheck)"),
        None => serve(),
    }
}

fn serve() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = Config::load()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building async runtime")?;
    runtime.block_on(async {
        let cancel = CancellationToken::new();
        tokio::spawn(shutdown_signal(cancel.clone()));
        hikvision_unifi_fire_bridge::run(cfg, cancel).await
    })
}

/// Cancel on SIGINT (interactive) or SIGTERM (container runtime `stop`).
async fn shutdown_signal(cancel: CancellationToken) {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(sigterm) => sigterm,
        Err(e) => {
            tracing::error!(error = %e, "cannot install SIGTERM handler");
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("SIGINT received; shutting down"),
        _ = sigterm.recv() => info!("SIGTERM received; shutting down"),
    }
    cancel.cancel();
}

/// Container HEALTHCHECK entry point: exit 0 only when the local health
/// endpoint answers 200. Plain std networking — no runtime, near-zero cost.
fn healthcheck() -> Result<()> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let bind = std::env::var("HEALTH_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let port = bind
        .parse::<std::net::SocketAddr>()
        .context("HEALTH_BIND must be an address:port pair")?
        .port();

    let addr = format!("127.0.0.1:{port}");
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().context("building healthcheck address")?,
        Duration::from_secs(2),
    )
    .with_context(|| format!("connecting to {addr}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let status_line = response.lines().next().unwrap_or_default();
    anyhow::ensure!(
        status_line.contains(" 200 "),
        "unexpected health response: {status_line}"
    );
    Ok(())
}
