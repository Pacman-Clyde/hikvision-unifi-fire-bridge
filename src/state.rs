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
    /// An edge was detected but suppressed by the cooldown. It is carried
    /// over and fires on a later `active` refresh once the cooldown has
    /// expired — a rate-limited edge must be delayed, never lost.
    pending_edge: bool,
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

    /// Upper bound on tracked sources. A real device has a handful of
    /// channels; a buggy or malicious camera inventing unique channel IDs
    /// must not grow memory without limit.
    const MAX_SOURCES: usize = 1024;

    /// Handle an `active` fire notification for `source`.
    pub fn on_active(&mut self, source: &str, now: Instant) -> Option<Alert> {
        if self.sources.len() >= Self::MAX_SOURCES && !self.sources.contains_key(source) {
            // Evict expired, non-pending sources; if everything is live the
            // new source falls back to the shared overflow slot so alerts
            // still fire (rate-limited) rather than being ignored.
            let ttl = self.cfg.active_ttl;
            self.sources.retain(|_, s| {
                s.pending_edge
                    || s.last_active_msg
                        .is_some_and(|t| now.duration_since(t) <= ttl)
            });
        }
        let key = if self.sources.len() >= Self::MAX_SOURCES && !self.sources.contains_key(source) {
            "overflow"
        } else {
            source
        };
        let state = self.sources.entry(key.to_owned()).or_default();
        let expired = state
            .last_active_msg
            .is_none_or(|t| now.duration_since(t) > self.cfg.active_ttl);
        let was_active = state.active && !expired;
        state.active = true;
        state.last_active_msg = Some(now);
        let cooldown_over = state
            .last_alert
            .is_none_or(|t| now.duration_since(t) >= self.cfg.cooldown);

        if !was_active || state.pending_edge {
            // Edge: a new fire (or one whose previous state expired), or a
            // previously rate-limited edge still waiting to fire.
            if cooldown_over {
                state.pending_edge = false;
                state.last_alert = Some(now);
                return Some(Alert::NewFire);
            }
            // Suppressed by the cooldown: remember the edge so it fires on a
            // later `active` refresh instead of being lost. This matters in
            // edge-only mode, where nothing else would ever retry it.
            state.pending_edge = true;
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

    /// Handle an `inactive` notification for `source`. A pending edge
    /// deliberately survives: a fire that started and was rate-limited still
    /// deserves its alert even if it went inactive in the meantime.
    pub fn on_inactive(&mut self, source: &str) {
        if let Some(state) = self.sources.get_mut(source) {
            state.active = false;
        }
    }

    /// Called when the camera stream drops or reconnects. Any `inactive`
    /// notification may have been lost during the gap, so no source may stay
    /// latched active: the next `active` message is treated as an edge again
    /// (still bounded by the cooldown, so a mid-fire reconnect cannot spam —
    /// and if the cooldown suppresses it, the pending-edge carryover
    /// guarantees it fires once the cooldown expires).
    pub fn on_stream_reset(&mut self) {
        for state in self.sources.values_mut() {
            state.active = false;
            state.last_active_msg = None;
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
        // New edge 10s later: rate-limited by cooldown, carried as pending.
        assert_eq!(t.on_active("1", t0 + Duration::from_secs(10)), None);
        // The pending edge fires as soon as an `active` refresh arrives past
        // the cooldown — a rate-limited edge is delayed, never lost.
        assert_eq!(
            t.on_active("1", t0 + COOLDOWN),
            Some(Alert::NewFire),
            "cooldown suppression must not silence an ongoing fire"
        );
    }

    #[test]
    fn suppressed_edge_is_carried_over_even_in_edge_only_mode() {
        // The kimi-review CRITICAL scenario: edge-only mode, second fire
        // starts within the cooldown, camera keeps refreshing `active` so the
        // state never expires. Without carryover this fire is never alerted.
        let mut t = edge_only();
        let t0 = Instant::now();
        assert_eq!(t.on_active("1", t0), Some(Alert::NewFire));
        t.on_inactive("1");
        // Second fire 10s later: suppressed by cooldown -> pending.
        assert_eq!(t.on_active("1", t0 + Duration::from_secs(10)), None);
        // Refreshes keep arriving inside the cooldown: still pending.
        assert_eq!(t.on_active("1", t0 + Duration::from_secs(30)), None);
        assert_eq!(t.on_active("1", t0 + Duration::from_secs(55)), None);
        // First refresh past the cooldown: the pending edge must fire.
        assert_eq!(
            t.on_active("1", t0 + COOLDOWN),
            Some(Alert::NewFire),
            "a rate-limited edge must fire once the cooldown expires"
        );
        // And it fires exactly once.
        assert_eq!(
            t.on_active("1", t0 + COOLDOWN + Duration::from_secs(5)),
            None
        );
    }

    #[test]
    fn reconnect_during_cooldown_cannot_silence_an_ongoing_fire() {
        // Edge-only mode: fire alerts, stream drops 1s later, camera
        // reconnects and keeps reporting `active` (fresh forever, so TTL
        // never expires). The post-reconnect edge is inside the cooldown.
        let mut t = edge_only();
        let t0 = Instant::now();
        assert_eq!(t.on_active("1", t0), Some(Alert::NewFire));
        t.on_stream_reset();
        assert_eq!(t.on_active("1", t0 + Duration::from_secs(5)), None);
        // Refreshes every 10s keep the state fresh across the cooldown edge.
        let mut now = t0 + Duration::from_secs(5);
        let mut alerts = 0;
        for _ in 0..12 {
            now += Duration::from_secs(10);
            if t.on_active("1", now).is_some() {
                alerts += 1;
            }
        }
        assert_eq!(
            alerts, 1,
            "the pending post-reconnect edge must fire exactly once after the cooldown"
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
    fn source_map_is_bounded_and_overflow_still_alerts() {
        let mut t = tracker();
        let t0 = Instant::now();
        // A hostile camera invents far more sources than the cap.
        for i in 0..(FireTracker::MAX_SOURCES + 100) {
            t.on_active(&format!("chan-{i}"), t0);
        }
        assert!(
            t.sources.len() <= FireTracker::MAX_SOURCES + 1,
            "tracked sources must stay bounded, got {}",
            t.sources.len()
        );
        // Overflow sources still alert (rate-limited through one slot).
        assert!(t.sources.contains_key("overflow"));
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
