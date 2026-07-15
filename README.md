# Hikvision → UniFi Protect Fire Bridge

A small Rust daemon that listens to a Hikvision (thermal) camera's ISAPI alert
stream and triggers a UniFi Protect Alarm Manager incoming webhook when a
fire-detection event occurs — so a camera fire alarm can ring a Protect siren,
send a priority push notification, or drive any other Alarm Manager action.

> **Safety notice:** this is an auxiliary automation component, **not**
> certified life-safety equipment. It must never replace compliant smoke
> alarms, fire panels, evacuation procedures, or emergency-services
> notification. Test the complete chain regularly.

## How it works

```text
Hikvision camera ──ISAPI alert stream──> bridge ──HTTPS webhook──> UniFi Protect
 (HTTP Digest auth)                        │                        Alarm Manager
                                           └── /healthz /readyz /status
```

- **Fail toward duplicate alerts, never missed ones.** Alerts trigger on the
  `inactive → active` edge, and by default **re-alert every 60 s while the
  fire stays active**. Active state expires if the camera goes quiet and is
  re-armed after every stream reconnect, so a lost `inactive` notification can
  never latch the alarm off.
- **Proactive path monitoring.** A periodic probe verifies DNS, routing, and
  TLS toward the Protect host, so a broken webhook path turns `/readyz` red
  *before* a fire, not during one.
- **Robust stream handling.** Byte-level frame extraction (UTF-8- and
  chunk-split-safe), structural XML parsing (namespace-agnostic), bounded
  buffers and queues, exponential reconnect backoff that resets after a
  healthy session.
- **Strict TLS.** Certificate validation toward Protect is always on. Plain
  HTTP is accepted only toward loopback addresses (for testing).
- **Hardened container.** Non-root, read-only-friendly, built-in Docker
  `HEALTHCHECK`, graceful SIGTERM shutdown.

## Quick start (Docker)

```bash
docker run -d \
  --name hikvision-unifi-fire-bridge \
  --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  -p 8080:8080 \
  -e HIKVISION_HOST=192.168.x.x \
  -e HIKVISION_USER=fire-bridge \
  -e HIKVISION_PASS='...' \
  -e PROTECT_BASE_URL=https://your-unvr-hostname \
  -e PROTECT_WEBHOOK_ID='...' \
  -e PROTECT_API_KEY='...' \
  ghcr.io/gasmanc/hikvision-unifi-fire-bridge:0.1.0
```

Pin a version tag or digest; do not auto-deploy `latest` for a
safety-related service.

## Configuration

| Variable | Required | Default | Description |
|---|---:|---|---|
| `HIKVISION_HOST` | Yes | — | Camera IP or hostname (optionally `host:port`) |
| `HIKVISION_USER` | Yes | — | Restricted camera account (events/ISAPI read only) |
| `HIKVISION_PASS` | Yes | — | Camera account password |
| `HIKVISION_SCHEME` | No | `http` | `http` or `https` toward the camera |
| `PROTECT_BASE_URL` | Yes* | — | HTTPS URL of the UNVR running Protect (certificate-valid hostname) |
| `PROTECT_WEBHOOK_ID` | Yes* | — | Alarm Manager incoming-webhook ID |
| `PROTECT_WEBHOOK_URL` | No | — | Full webhook URL override; replaces `PROTECT_BASE_URL` + `PROTECT_WEBHOOK_ID` if your Protect version uses a different path |
| `PROTECT_API_KEY` | Yes | — | Protect integration API key (sent as `X-API-Key`) |
| `FIRE_EVENT_TYPES` | No | `fireDetection,fire_detection,fireAlarm` | Comma-separated `eventType` values treated as fire (case-insensitive) |
| `FIRE_COOLDOWN_SECONDS` | No | `60` | Minimum gap between edge-trigger alerts per source |
| `FIRE_REALERT_SECONDS` | No | `60` | Re-alert interval while a fire stays active; `0` disables re-alerting |
| `FIRE_ACTIVE_TTL_SECONDS` | No | `300` | Active state expires after this silence (anti-latch safety) |
| `PROTECT_PROBE_SECONDS` | No | `60` | Protect reachability probe interval; `0` disables |
| `STREAM_IDLE_TIMEOUT_SECONDS` | No | `90` | Reconnect when the camera stream is silent this long |
| `WEBHOOK_TIMEOUT_SECONDS` | No | `5` | Per-attempt webhook timeout |
| `WEBHOOK_ATTEMPTS` | No | `3` | Delivery attempts (permanent 4xx errors are not retried) |
| `RECONNECT_INITIAL_SECONDS` | No | `1` | First reconnect delay |
| `RECONNECT_MAX_SECONDS` | No | `30` | Reconnect delay ceiling |
| `HEALTH_BIND` | No | `0.0.0.0:8080` | Health server bind address |
| `RUST_LOG` | No | `info` | Tracing filter |

\* Not required when `PROTECT_WEBHOOK_URL` is set.

## Health endpoints

| Endpoint | Meaning |
|---|---|
| `GET /healthz` | Process liveness (also used by the container `HEALTHCHECK`) |
| `GET /readyz` | `200` only when the camera stream is connected, the Protect probe passes, and the last alert delivery did not fail |
| `GET /status` | Full diagnostic JSON: timestamps, reconnect/malformed/dropped counters, last errors (sanitised — no secrets, no URLs) |

A **failed alert delivery latches `/readyz` unready** until a later delivery
succeeds. That is deliberate: a missed alarm needs a human. Monitor `/readyz`
with something independent of UniFi (e.g. Uptime Kuma) — Protect cannot report
the failure of the path used to reach Protect.

## Finding your camera's event type

Firmwares differ. Capture a test event and check the `eventType`:

```bash
curl --digest --user 'fire-bridge:PASSWORD' --no-buffer \
  'http://CAMERA/ISAPI/Event/notification/alertStream'
```

If yours differs from the defaults, set `FIRE_EVENT_TYPES` — no rebuild needed.

## Verifying the Protect webhook

Protect UI and API paths can move between versions. Test yours directly:

```bash
curl --fail-with-body -X POST \
  -H "X-API-Key: $PROTECT_API_KEY" \
  "https://YOUR_UNVR/proxy/protect/integration/v1/alarm-manager/webhook/$PROTECT_WEBHOOK_ID"
```

If your Protect version exposes a different URL, pass it verbatim via
`PROTECT_WEBHOOK_URL`.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test            # unit + end-to-end tests (fake camera & Protect servers)
```

Releases are tagged `vX.Y.Z`; CI builds and publishes the container image to
`ghcr.io/gasmanc/hikvision-unifi-fire-bridge`.

## Security

- Use a dedicated, least-privilege camera account and a minimum-scope Protect
  API key; rotate on any suspected exposure.
- TLS certificate validation is always enforced toward Protect and cannot be
  disabled.
- Restrict the health port to your monitoring network.
- Report vulnerabilities via GitHub private vulnerability reporting.

## License

Copyright © 2026 contributors.

Licensed under the GNU Affero General Public License, version 3 or later
([LICENSE](LICENSE), `AGPL-3.0-or-later`).
