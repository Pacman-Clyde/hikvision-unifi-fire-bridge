//! End-to-end tests: the complete pipeline against a fake Hikvision camera
//! (with a real Digest challenge) and a fake Protect webhook receiver.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::header::HeaderValue;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use url::Url;

use hikvision_unifi_fire_bridge::config::{Config, FireMatcher};
use hikvision_unifi_fire_bridge::run;

const API_KEY: &str = "e2e-test-key";
const DIGEST_CHALLENGE: &str = r#"Digest realm="hikvision", nonce="e2e0123456789", qop="auth""#;

/// Fake camera: enforces a Digest challenge, then streams whatever the test
/// feeds through the next queued channel. One queued receiver per connection.
#[derive(Clone)]
struct CameraState {
    receivers: Arc<Mutex<VecDeque<mpsc::Receiver<Bytes>>>>,
    challenges: Arc<AtomicU32>,
    authorized: Arc<AtomicU32>,
}

async fn camera_handler(State(state): State<CameraState>, headers: HeaderMap) -> Response {
    let auth = headers.get(header::AUTHORIZATION);
    match auth {
        None => {
            state.challenges.fetch_add(1, Ordering::SeqCst);
            (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, DIGEST_CHALLENGE)],
            )
                .into_response()
        }
        Some(value) => {
            let value = value.to_str().unwrap_or_default();
            assert!(
                value.starts_with("Digest") && value.contains(r#"username="fire-bridge""#),
                "camera must receive a Digest authorization, got: {value}"
            );
            state.authorized.fetch_add(1, Ordering::SeqCst);
            let receiver = state.receivers.lock().unwrap().pop_front();
            match receiver {
                Some(receiver) => {
                    let stream = ReceiverStream::new(receiver).map(Ok::<_, Infallible>);
                    (
                        [(header::CONTENT_TYPE, "multipart/mixed; boundary=boundary")],
                        Body::from_stream(stream),
                    )
                        .into_response()
                }
                None => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            }
        }
    }
}

/// Fake Protect: records webhook hits after validating the API key.
#[derive(Clone)]
struct ProtectState {
    hits: mpsc::Sender<()>,
}

async fn protect_handler(State(state): State<ProtectState>, headers: HeaderMap) -> StatusCode {
    if headers.get("X-API-Key").and_then(|v| v.to_str().ok()) != Some(API_KEY) {
        return StatusCode::FORBIDDEN;
    }
    let _ = state.hits.send(()).await;
    StatusCode::OK
}

struct Harness {
    camera: CameraState,
    protect_hits: mpsc::Receiver<()>,
    cancel: CancellationToken,
}

async fn start_harness(configure: impl FnOnce(&mut Config)) -> Harness {
    let camera = CameraState {
        receivers: Arc::new(Mutex::new(VecDeque::new())),
        challenges: Arc::new(AtomicU32::new(0)),
        authorized: Arc::new(AtomicU32::new(0)),
    };
    let camera_addr = serve(
        Router::new()
            .route("/ISAPI/Event/notification/alertStream", get(camera_handler))
            .with_state(camera.clone()),
    )
    .await;

    let (hits_tx, protect_hits) = mpsc::channel(64);
    let protect_addr = serve(
        Router::new()
            .route("/hook/{id}", post(protect_handler))
            .with_state(ProtectState { hits: hits_tx }),
    )
    .await;

    let mut cfg = Config {
        hik_url: Url::parse(&format!(
            "http://{camera_addr}/ISAPI/Event/notification/alertStream"
        ))
        .unwrap(),
        hik_user: "fire-bridge".into(),
        hik_pass: "e2e-password".into(),
        webhook_url: Url::parse(&format!("http://{protect_addr}/hook/test-webhook")).unwrap(),
        api_key: HeaderValue::from_static(API_KEY),
        probe_url: Url::parse(&format!("http://{protect_addr}/")).unwrap(),
        health_bind: "127.0.0.1:0".parse().unwrap(),
        fire_matcher: FireMatcher::default(),
        stream_idle: Duration::from_secs(10),
        cooldown: Duration::from_millis(400),
        realert: None,
        active_ttl: Duration::from_secs(10),
        webhook_timeout: Duration::from_secs(2),
        webhook_attempts: 2,
        probe_interval: None,
        reconnect_initial: Duration::from_millis(50),
        reconnect_max: Duration::from_millis(200),
    };
    configure(&mut cfg);

    let cancel = CancellationToken::new();
    let run_cancel = cancel.clone();
    let run_cfg = cfg.clone();
    tokio::spawn(async move { run(run_cfg, run_cancel).await });

    Harness {
        camera,
        protect_hits,
        cancel,
    }
}

impl Harness {
    /// Queue a fresh camera connection and return its feed.
    fn connect_camera(&self) -> mpsc::Sender<Bytes> {
        let (tx, rx) = mpsc::channel(16);
        self.camera.receivers.lock().unwrap().push_back(rx);
        tx
    }

    async fn expect_webhook(&mut self, why: &str) {
        timeout(Duration::from_secs(5), self.protect_hits.recv())
            .await
            .unwrap_or_else(|_| panic!("expected a webhook delivery: {why}"))
            .expect("hit channel closed");
    }

    async fn expect_no_webhook(&mut self, window: Duration, why: &str) {
        if timeout(window, self.protect_hits.recv()).await.is_ok() {
            panic!("unexpected webhook delivery: {why}");
        }
    }
}

async fn serve(app: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

fn event(event_type: &str, state: &str) -> Bytes {
    Bytes::from(format!(
        "--boundary\r\nContent-Type: application/xml\r\nContent-Length: 0\r\n\r\n\
         <EventNotificationAlert version=\"2.0\" xmlns=\"http://www.hikvision.com/ver20/XMLSchema\">\
         <channelID>1</channelID>\
         <eventType>{event_type}</eventType>\
         <eventState>{state}</eventState>\
         </EventNotificationAlert>\r\n"
    ))
}

#[tokio::test]
async fn fire_event_is_delivered_through_digest_auth() {
    let mut h = start_harness(|_| {}).await;
    let feed = h.connect_camera();

    feed.send(event("fireDetection", "active")).await.unwrap();
    h.expect_webhook("first active fire event").await;

    assert!(
        h.camera.challenges.load(Ordering::SeqCst) >= 1,
        "camera must have issued a digest challenge"
    );
    assert!(h.camera.authorized.load(Ordering::SeqCst) >= 1);
    h.cancel.cancel();
}

#[tokio::test]
async fn repeated_active_is_deduplicated_in_edge_mode() {
    let mut h = start_harness(|cfg| {
        cfg.cooldown = Duration::from_secs(60);
    })
    .await;
    let feed = h.connect_camera();

    feed.send(event("fireDetection", "active")).await.unwrap();
    h.expect_webhook("first active").await;

    for _ in 0..3 {
        feed.send(event("fireDetection", "active")).await.unwrap();
    }
    h.expect_no_webhook(
        Duration::from_millis(700),
        "repeated active notifications for the same ongoing fire",
    )
    .await;
    h.cancel.cancel();
}

#[tokio::test]
async fn ongoing_fire_realerts_at_the_configured_interval() {
    let mut h = start_harness(|cfg| {
        cfg.realert = Some(Duration::from_millis(300));
        cfg.cooldown = Duration::from_secs(60);
    })
    .await;
    let feed = h.connect_camera();

    feed.send(event("fireDetection", "active")).await.unwrap();
    h.expect_webhook("first active").await;

    // Camera keeps repeating `active` (as Hikvision firmware does).
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(60)).await;
        feed.send(event("fireDetection", "active")).await.unwrap();
    }
    h.expect_webhook("re-alert for ongoing fire").await;
    h.cancel.cancel();
}

#[tokio::test]
async fn non_fire_events_never_trigger() {
    let mut h = start_harness(|_| {}).await;
    let feed = h.connect_camera();

    feed.send(event("videoloss", "active")).await.unwrap();
    feed.send(event("motiondetection", "active")).await.unwrap();
    h.expect_no_webhook(Duration::from_millis(700), "non-fire event types")
        .await;

    // The pipeline must still be alive for a real fire afterwards.
    feed.send(event("fireDetection", "active")).await.unwrap();
    h.expect_webhook("fire event after non-fire noise").await;
    h.cancel.cancel();
}

#[tokio::test]
async fn stream_drop_cannot_latch_the_alarm_off() {
    let mut h = start_harness(|cfg| {
        cfg.cooldown = Duration::from_millis(300);
    })
    .await;

    // Fire starts; alert delivered.
    let feed = h.connect_camera();
    feed.send(event("fireDetection", "active")).await.unwrap();
    h.expect_webhook("first fire").await;

    // Stream drops mid-fire; the `inactive` is never delivered. The bridge
    // retries (hitting 503 while no fresh connection is queued) with backoff.
    drop(feed);

    // Let the cooldown pass while the bridge is reconnecting.
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Provide a fresh connection; a fire event on it must alert again —
    // a lost `inactive` must never leave the alarm latched off.
    let feed2 = h.connect_camera();
    feed2.send(event("fireDetection", "active")).await.unwrap();
    h.expect_webhook("fire after stream drop must still alert")
        .await;
    h.cancel.cancel();
}

#[tokio::test]
async fn fire_type_and_state_matching_is_case_insensitive() {
    let mut h = start_harness(|_| {}).await;
    let feed = h.connect_camera();
    feed.send(event("FIREALARM", "Active")).await.unwrap();
    h.expect_webhook("case-insensitive fire type and state")
        .await;
    h.cancel.cancel();
}

#[tokio::test]
async fn config_from_map_to_running_bridge() {
    // Exercise the env-map constructor against live loopback servers to prove
    // the http-toward-loopback test path works end to end.
    let camera = CameraState {
        receivers: Arc::new(Mutex::new(VecDeque::new())),
        challenges: Arc::new(AtomicU32::new(0)),
        authorized: Arc::new(AtomicU32::new(0)),
    };
    let camera_addr = serve(
        Router::new()
            .route("/ISAPI/Event/notification/alertStream", get(camera_handler))
            .with_state(camera.clone()),
    )
    .await;
    let (hits_tx, mut hits_rx) = mpsc::channel(8);
    let protect_addr = serve(
        Router::new()
            .route("/hook/{id}", post(protect_handler))
            .with_state(ProtectState { hits: hits_tx }),
    )
    .await;

    let vars: std::collections::HashMap<String, String> = [
        ("HIKVISION_HOST".to_owned(), camera_addr.to_string()),
        ("HIKVISION_USER".to_owned(), "fire-bridge".to_owned()),
        ("HIKVISION_PASS".to_owned(), "e2e-password".to_owned()),
        (
            "PROTECT_WEBHOOK_URL".to_owned(),
            format!("http://{protect_addr}/hook/map-test"),
        ),
        ("PROTECT_API_KEY".to_owned(), API_KEY.to_owned()),
        ("HEALTH_BIND".to_owned(), "127.0.0.1:0".to_owned()),
        ("PROTECT_PROBE_SECONDS".to_owned(), "1".to_owned()),
    ]
    .into_iter()
    .collect();
    let cfg = Config::from_map(&vars).expect("valid loopback configuration");

    let (tx, rx) = mpsc::channel(16);
    camera.receivers.lock().unwrap().push_back(rx);
    let cancel = CancellationToken::new();
    let run_cancel = cancel.clone();
    tokio::spawn(async move { run(cfg, run_cancel).await });

    tx.send(event("fireDetection", "active")).await.unwrap();
    timeout(Duration::from_secs(5), hits_rx.recv())
        .await
        .expect("webhook must be delivered from env-map config")
        .unwrap();
    cancel.cancel();
}
