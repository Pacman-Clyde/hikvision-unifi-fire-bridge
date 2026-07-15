//! Per-source fire alarm state machine.
//!
//! Design goals, in priority order:
//! 1. Never silently suppress a real fire (fail toward duplicate alerts).
//! 2. Do not spam Protect with one alert per repeated `active` notification.
//!
//! Three mechanisms cooperate:
//! - **Edge triggering**: an `inactive -> active` transition alerts immediately,
//!   subject to a per-source cooldown that bounds the total alert rate.
//! - **Re-alerting**: while a fire stays active, each repeated `active`
//!   notification re-alerts once per re-alert interval, so an ongoing fire
//!   keeps the Protect automation firing. Optional.
//! - **Staleness expiry**: an `active` state that has not been refreshed within
//!   the TTL is treated as expired, so a lost `inactive` notification (camera
//!   reboot, stream drop) can never latch the alarm off forever.
//!
//! The tracker is a pure, clock-injected state machine so every rule above is
//! unit-testable without real time.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Why an alert was raised. Carried through to logs and the webhook worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alert {
    /// A source transitioned from not-active (or expired) to active.
    NewFire,
    /// A source remains active and the re-alert interval elapsed.
    StillActive,
}

#[derive(Debug, Clone)]
pub struct TrackerConfig {
    /// Minimum gap between edge-trigger alerts for one source.
    pub cooldown: Duration,
    /// Re-alert interval while a source stays active. `None` = edge-only.
    pub realert: Option<Duration>,
    /// An active state older than this (no refreshed `active` message) is
    /// treated as expired, so the next `active` is a new fire.
    pub active_ttl: Duration,
}

#[derive(Debug, Default)]
struct SourceState {
    active: bool,
    last_active_msg: Option<Instant>,
    last_alert: Option<Instant>,
}

#[derive(Debug)]
pub struct FireTracker {
    cfg: TrackerConfig,
    sources: HashMap<String, SourceState>,
}

impl FireTracker {
    pub fn new(cfg: TrackerConfig) -> Self {
        Self {
            cfg,
            sources: HashMap::new(),
        }
    }

    /// Handle an `active` fire notification for `source`.
    pub fn on_active(&mut self, source: &str, now: Instant) -> Option<Alert> {
        let state = self.sources.entry(source.to_owned()).or_default();
        let expired = state
            .last_active_msg
            .is_none_or(|t| now.duration_since(t) > self.cfg.active_ttl);
        let was_active = state.active && !expired;
        state.active = true;
        state.last_active_msg = Some(now);

        if !was_active {
            // Edge: a new fire (or one whose previous state expired).
            if state
                .last_alert
                .is_none_or(|t| now.duration_since(t) >= self.cfg.cooldown)
            {
                state.last_alert = Some(now);
                return Some(Alert::NewFire);
            }
            // Suppressed by cooldown. If re-alerting is enabled the next
            // repeated `active` message will still get through below.
            return None;
        }

        if let Some(interval) = self.cfg.realert
            && state
                .last_alert
                .is_none_or(|t| now.duration_since(t) >= interval)
        {
            state.last_alert = Some(now);
            return Some(Alert::StillActive);
        }
        None
    }

    /// Handle an `inactive` notification for `source`.
    pub fn on_inactive(&mut self, source: &str) {
        if let Some(state) = self.sources.get_mut(source) {
            state.active = false;
        }
    }

    /// Called when the camera stream drops or reconnects. Any `inactive`
    /// notification may have been lost during the gap, so no source may stay
    /// latched active: the next `active` message is treated as an edge again
    /// (still bounded by the cooldown, so a mid-fire reconnect cannot spam).
    pub fn on_stream_reset(&mut self) {
        for state in self.sources.values_mut() {
            state.active = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COOLDOWN: Duration = Duration::from_secs(60);
    const REALERT: Duration = Duration::from_secs(60);
    const TTL: Duration = Duration::from_secs(300);

    fn tracker() -> FireTracker {
        FireTracker::new(TrackerConfig {
            cooldown: COOLDOWN,
            realert: Some(REALERT),
            active_ttl: TTL,
        })
    }

    fn edge_only() -> FireTracker {
        FireTracker::new(TrackerConfig {
            cooldown: COOLDOWN,
            realert: None,
            active_ttl: TTL,
        })
    }

    #[test]
    fn first_active_alerts_immediately() {
        let mut t = tracker();
        assert_eq!(t.on_active("1", Instant::now()), Some(Alert::NewFire));
    }

    #[test]
    fn repeated_active_within_realert_interval_is_suppressed() {
        let mut t = tracker();
        let t0 = Instant::now();
        assert_eq!(t.on_active("1", t0), Some(Alert::NewFire));
        assert_eq!(t.on_active("1", t0 + Duration::from_secs(5)), None);
        assert_eq!(t.on_active("1", t0 + Duration::from_secs(30)), None);
    }

    #[test]
    fn ongoing_fire_realerts_every_interval() {
        let mut t = tracker();
        let t0 = Instant::now();
        assert_eq!(t.on_active("1", t0), Some(Alert::NewFire));
        assert_eq!(
            t.on_active("1", t0 + REALERT),
            Some(Alert::StillActive),
            "ongoing fire must re-alert after the interval"
        );
        assert_eq!(
            t.on_active("1", t0 + REALERT + Duration::from_secs(5)),
            None
        );
        assert_eq!(t.on_active("1", t0 + REALERT * 2), Some(Alert::StillActive));
    }

    #[test]
    fn edge_only_mode_never_realerts_while_state_is_fresh() {
        let mut t = edge_only();
        let t0 = Instant::now();
        assert_eq!(t.on_active("1", t0), Some(Alert::NewFire));
        // Repeated `active` refreshes that stay within the TTL: never re-alert.
        let mut now = t0;
        for _ in 0..20 {
            now += TTL / 2;
            assert_eq!(t.on_active("1", now), None);
        }
        // But once refreshes STOP for longer than the TTL, the next active is
        // indistinguishable from a new fire and must alert even in edge mode.
        assert_eq!(
            t.on_active("1", now + TTL + Duration::from_secs(1)),
            Some(Alert::NewFire)
        );
    }

    #[test]
    fn inactive_then_active_after_cooldown_is_a_new_fire() {
        let mut t = edge_only();
        let t0 = Instant::now();
        assert_eq!(t.on_active("1", t0), Some(Alert::NewFire));
        t.on_inactive("1");
        assert_eq!(
            t.on_active("1", t0 + COOLDOWN),
            Some(Alert::NewFire),
            "a fresh fire after the cooldown must alert"
        );
    }

    #[test]
    fn inactive_then_active_within_cooldown_is_suppressed_but_recovers() {
        let mut t = tracker();
        let t0 = Instant::now();
        assert_eq!(t.on_active("1", t0), Some(Alert::NewFire));
        t.on_inactive("1");
        // New edge 10s later: rate-limited by cooldown.
        assert_eq!(t.on_active("1", t0 + Duration::from_secs(10)), None);
        // But the fire is still burning: repeated active messages re-alert
        // once the re-alert interval from the last alert has elapsed.
        assert_eq!(
            t.on_active("1", t0 + REALERT),
            Some(Alert::StillActive),
            "cooldown suppression must not silence an ongoing fire"
        );
    }

    #[test]
    fn lost_inactive_cannot_latch_the_alarm_off() {
        // The critical missed-alarm scenario: fire -> stream drop -> fire went
        // inactive unseen -> much later a NEW fire starts.
        let mut t = edge_only();
        let t0 = Instant::now();
        assert_eq!(t.on_active("1", t0), Some(Alert::NewFire));
        // No inactive ever arrives. A new fire starts after the TTL.
        let later = t0 + TTL + Duration::from_secs(1);
        assert_eq!(
            t.on_active("1", later),
            Some(Alert::NewFire),
            "expired active state must be treated as a new fire"
        );
    }

    #[test]
    fn stream_reset_rearms_edge_triggering() {
        let mut t = edge_only();
        let t0 = Instant::now();
        assert_eq!(t.on_active("1", t0), Some(Alert::NewFire));
        t.on_stream_reset();
        // Active again right after reconnect: same fire, inside cooldown -> no
        // duplicate spam.
        assert_eq!(t.on_active("1", t0 + Duration::from_secs(5)), None);
        t.on_stream_reset();
        // Active after reconnect and past cooldown: cannot be distinguished
        // from a new fire, so it must alert (fail toward duplicates).
        assert_eq!(t.on_active("1", t0 + COOLDOWN), Some(Alert::NewFire));
    }

    #[test]
    fn sources_are_tracked_independently() {
        let mut t = tracker();
        let t0 = Instant::now();
        assert_eq!(t.on_active("1", t0), Some(Alert::NewFire));
        assert_eq!(
            t.on_active("2", t0 + Duration::from_secs(1)),
            Some(Alert::NewFire),
            "a second channel must not be rate-limited by the first"
        );
    }

    #[test]
    fn inactive_for_unknown_source_is_a_noop() {
        let mut t = tracker();
        t.on_inactive("never-seen");
        assert_eq!(
            t.on_active("never-seen", Instant::now()),
            Some(Alert::NewFire)
        );
    }
}
