//! Environment-driven configuration.
//!
//! Rules:
//! - Required variables fail fast at startup with the variable *name* only —
//!   secret values are never echoed into logs or errors.
//! - The Protect webhook must be HTTPS with normal certificate validation.
//!   Plain HTTP is permitted only toward loopback addresses (local testing).
//! - Every tunable has a safe default; zero disables optional behaviours.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use reqwest::header::HeaderValue;
use url::{Host, Url};

/// Case-insensitive matcher for fire-relevant `eventType` values.
#[derive(Debug, Clone)]
pub struct FireMatcher {
    types: Vec<String>,
}

impl FireMatcher {
    pub const DEFAULT_TYPES: &[&str] = &["firedetection", "fire_detection", "firealarm"];

    fn from_csv(csv: &str) -> Result<Self> {
        let types: Vec<String> = csv
            .split(',')
            .map(|t| t.trim().to_ascii_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        if types.is_empty() {
            bail!("FIRE_EVENT_TYPES must list at least one event type");
        }
        Ok(Self { types })
    }

    pub fn matches(&self, event_type: &str) -> bool {
        let normalised = event_type.trim().to_ascii_lowercase();
        self.types.contains(&normalised)
    }
}

impl Default for FireMatcher {
    fn default() -> Self {
        Self {
            types: Self::DEFAULT_TYPES.iter().map(|t| t.to_string()).collect(),
        }
    }
}

#[derive(Clone)]
pub struct Config {
    pub hik_url: Url,
    pub hik_user: String,
    pub hik_pass: String,
    pub webhook_url: Url,
    pub api_key: HeaderValue,
    /// URL probed periodically to verify the Protect path (DNS, routing, TLS).
    pub probe_url: Url,
    pub health_bind: SocketAddr,
    pub fire_matcher: FireMatcher,
    pub stream_idle: Duration,
    pub cooldown: Duration,
    pub realert: Option<Duration>,
    pub active_ttl: Duration,
    pub webhook_timeout: Duration,
    pub webhook_attempts: u32,
    pub probe_interval: Option<Duration>,
    pub reconnect_initial: Duration,
    pub reconnect_max: Duration,
}

/// Hand-written so an incidental `{:?}` (debug log, panic context, `dbg!`)
/// can never print the camera password. The API key is additionally marked
/// sensitive at construction, so `HeaderValue`'s own Debug prints
/// `Sensitive` instead of the value.
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("hik_url", &self.hik_url.as_str())
            .field("hik_user", &self.hik_user)
            .field("hik_pass", &"<redacted>")
            .field("webhook_url", &"<redacted>")
            .field("api_key", &self.api_key)
            .field("probe_url", &self.probe_url.as_str())
            .field("health_bind", &self.health_bind)
            .field("fire_matcher", &self.fire_matcher)
            .field("stream_idle", &self.stream_idle)
            .field("cooldown", &self.cooldown)
            .field("realert", &self.realert)
            .field("active_ttl", &self.active_ttl)
            .field("webhook_timeout", &self.webhook_timeout)
            .field("webhook_attempts", &self.webhook_attempts)
            .field("probe_interval", &self.probe_interval)
            .field("reconnect_initial", &self.reconnect_initial)
            .field("reconnect_max", &self.reconnect_max)
            .finish()
    }
}

impl Config {
    /// Load from the process environment.
    pub fn load() -> Result<Self> {
        Self::from_map(&std::env::vars().collect())
    }

    /// Load from an explicit map (unit tests).
    pub fn from_map(vars: &HashMap<String, String>) -> Result<Self> {
        let get = |name: &str| vars.get(name).map(String::as_str).map(str::trim);
        let required = |name: &str| -> Result<String> {
            match get(name) {
                Some(v) if !v.is_empty() => Ok(v.to_owned()),
                _ => bail!("{name} is required and must not be empty"),
            }
        };

        let scheme = get("HIKVISION_SCHEME").unwrap_or("http");
        if !matches!(scheme, "http" | "https") {
            bail!("HIKVISION_SCHEME must be http or https");
        }
        let hik_host = required("HIKVISION_HOST")?;
        // A bare host or host:port only. Anything else (userinfo, path,
        // query) would silently change the request target and could leak
        // into error strings.
        if hik_host.contains(['/', '@', '?', '#', '\\']) || hik_host.contains(char::is_whitespace) {
            bail!("HIKVISION_HOST must be a bare host or host:port (no path, userinfo, or query)");
        }
        let hik_url = Url::parse(&format!(
            "{scheme}://{hik_host}/ISAPI/Event/notification/alertStream"
        ))
        .context("HIKVISION_HOST is not a valid host")?;

        let webhook_url = match get("PROTECT_WEBHOOK_URL").filter(|v| !v.is_empty()) {
            Some(full) => Url::parse(full).context("PROTECT_WEBHOOK_URL is not a valid URL")?,
            None => {
                let base = Url::parse(&required("PROTECT_BASE_URL")?)
                    .context("PROTECT_BASE_URL is not a valid URL")?;
                let webhook_id = required("PROTECT_WEBHOOK_ID")?;
                // The ID lands in a URL path: restrict its alphabet so a
                // value like `../..` cannot be path-normalised into a
                // different endpoint. Use PROTECT_WEBHOOK_URL for exotic
                // Protect paths instead.
                if !webhook_id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    bail!(
                        "PROTECT_WEBHOOK_ID may contain only letters, digits, '-' and '_' \
                         (set PROTECT_WEBHOOK_URL for a full custom URL)"
                    );
                }
                base.join(&format!(
                    "/proxy/protect/integration/v1/alarm-manager/webhook/{webhook_id}"
                ))
                .context("could not build webhook URL from PROTECT_BASE_URL")?
            }
        };
        require_https_or_loopback(&webhook_url, "Protect webhook URL")?;

        let probe_url = match get("PROTECT_BASE_URL").filter(|v| !v.is_empty()) {
            Some(base) => Url::parse(base).context("PROTECT_BASE_URL is not a valid URL")?,
            None => origin_of(&webhook_url)?,
        };
        require_https_or_loopback(&probe_url, "Protect probe URL")?;

        let mut api_key = HeaderValue::from_str(&required("PROTECT_API_KEY")?)
            .context("PROTECT_API_KEY contains characters not permitted in an HTTP header")?;
        // Debug-formatting a sensitive HeaderValue prints `Sensitive`, not
        // the key.
        api_key.set_sensitive(true);

        let fire_matcher = match get("FIRE_EVENT_TYPES").filter(|v| !v.is_empty()) {
            Some(csv) => FireMatcher::from_csv(csv)?,
            None => FireMatcher::default(),
        };

        let seconds = |name: &str, default: u64| -> Result<Duration> {
            let raw = get(name).map(str::to_owned).unwrap_or(default.to_string());
            let value: u64 = raw
                .parse()
                .with_context(|| format!("{name} must be a whole number of seconds"))?;
            Ok(Duration::from_secs(value))
        };
        let optional_seconds = |name: &str, default: u64| -> Result<Option<Duration>> {
            let value = seconds(name, default)?;
            Ok((!value.is_zero()).then_some(value))
        };
        // Zero would make timeouts fire instantly and degenerate the state
        // machine (TTL=0 turns every heartbeat into an "expired" edge;
        // cooldown=0 removes all rate limiting). Fail fast instead.
        let nonzero_seconds = |name: &str, default: u64| -> Result<Duration> {
            let value = seconds(name, default)?;
            if value.is_zero() {
                bail!("{name} must be greater than zero");
            }
            Ok(value)
        };

        let webhook_attempts: u32 = get("WEBHOOK_ATTEMPTS")
            .unwrap_or("3")
            .parse()
            .context("WEBHOOK_ATTEMPTS must be a whole number")?;
        if webhook_attempts == 0 {
            bail!("WEBHOOK_ATTEMPTS must be at least 1");
        }

        let reconnect_initial = seconds("RECONNECT_INITIAL_SECONDS", 1)?;
        let reconnect_max = seconds("RECONNECT_MAX_SECONDS", 30)?;
        if reconnect_initial.is_zero() || reconnect_max < reconnect_initial {
            bail!("RECONNECT_MAX_SECONDS must be >= RECONNECT_INITIAL_SECONDS >= 1");
        }
        if reconnect_max > Duration::from_secs(3600) {
            // An accidental huge ceiling would leave the camera path down for
            // hours after a burst of failures.
            bail!("RECONNECT_MAX_SECONDS must be at most 3600");
        }

        Ok(Self {
            hik_url,
            hik_user: required("HIKVISION_USER")?,
            hik_pass: required("HIKVISION_PASS")?,
            webhook_url,
            api_key,
            probe_url,
            health_bind: get("HEALTH_BIND")
                .unwrap_or("0.0.0.0:8080")
                .parse()
                .context("HEALTH_BIND must be an address:port pair")?,
            fire_matcher,
            stream_idle: nonzero_seconds("STREAM_IDLE_TIMEOUT_SECONDS", 90)?,
            cooldown: nonzero_seconds("FIRE_COOLDOWN_SECONDS", 60)?,
            realert: optional_seconds("FIRE_REALERT_SECONDS", 60)?,
            active_ttl: nonzero_seconds("FIRE_ACTIVE_TTL_SECONDS", 300)?,
            webhook_timeout: nonzero_seconds("WEBHOOK_TIMEOUT_SECONDS", 5)?,
            webhook_attempts,
            probe_interval: optional_seconds("PROTECT_PROBE_SECONDS", 60)?,
            reconnect_initial,
            reconnect_max,
        })
    }
}

fn require_https_or_loopback(url: &Url, what: &str) -> Result<()> {
    if url.scheme() == "https" {
        return Ok(());
    }
    let loopback = match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    };
    if url.scheme() == "http" && loopback {
        return Ok(());
    }
    bail!("{what} must use https (plain http is allowed only toward loopback, for testing)");
}

fn origin_of(url: &Url) -> Result<Url> {
    let mut origin = url.clone();
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    Ok(origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_vars() -> HashMap<String, String> {
        [
            ("HIKVISION_HOST", "192.0.2.10"),
            ("HIKVISION_USER", "hik-operator"),
            ("HIKVISION_PASS", "secret"),
            ("PROTECT_BASE_URL", "https://protect.example.com"),
            ("PROTECT_WEBHOOK_ID", "abc123"),
            ("PROTECT_API_KEY", "key123"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
    }

    #[test]
    fn minimal_configuration_loads_with_safe_defaults() {
        let cfg = Config::from_map(&base_vars()).unwrap();
        assert_eq!(
            cfg.hik_url.as_str(),
            "http://192.0.2.10/ISAPI/Event/notification/alertStream"
        );
        assert_eq!(
            cfg.webhook_url.as_str(),
            "https://protect.example.com/proxy/protect/integration/v1/alarm-manager/webhook/abc123"
        );
        assert_eq!(cfg.probe_url.as_str(), "https://protect.example.com/");
        assert_eq!(cfg.stream_idle, Duration::from_secs(90));
        assert_eq!(cfg.cooldown, Duration::from_secs(60));
        assert_eq!(cfg.realert, Some(Duration::from_secs(60)));
        assert_eq!(cfg.active_ttl, Duration::from_secs(300));
        assert_eq!(cfg.webhook_attempts, 3);
        assert_eq!(cfg.probe_interval, Some(Duration::from_secs(60)));
    }

    #[test]
    fn missing_required_variable_names_the_variable_without_values() {
        let mut vars = base_vars();
        vars.remove("PROTECT_API_KEY");
        let err = format!("{:#}", Config::from_map(&vars).unwrap_err());
        assert!(err.contains("PROTECT_API_KEY"), "err={err}");
        assert!(!err.contains("secret"), "must not echo other values: {err}");
    }

    #[test]
    fn empty_required_variable_is_rejected() {
        let mut vars = base_vars();
        vars.insert("HIKVISION_PASS".into(), "  ".into());
        assert!(Config::from_map(&vars).is_err());
    }

    #[test]
    fn full_webhook_url_override_takes_precedence() {
        let mut vars = base_vars();
        vars.insert(
            "PROTECT_WEBHOOK_URL".into(),
            "https://protect.example.com/some/other/path/hook1".into(),
        );
        let cfg = Config::from_map(&vars).unwrap();
        assert_eq!(
            cfg.webhook_url.as_str(),
            "https://protect.example.com/some/other/path/hook1"
        );
    }

    #[test]
    fn webhook_override_alone_is_sufficient() {
        let mut vars = base_vars();
        vars.remove("PROTECT_BASE_URL");
        vars.remove("PROTECT_WEBHOOK_ID");
        vars.insert(
            "PROTECT_WEBHOOK_URL".into(),
            "https://unvr.example.net/hook/xyz".into(),
        );
        let cfg = Config::from_map(&vars).unwrap();
        assert_eq!(cfg.probe_url.as_str(), "https://unvr.example.net/");
    }

    #[test]
    fn non_https_webhook_is_rejected() {
        let mut vars = base_vars();
        vars.insert(
            "PROTECT_BASE_URL".into(),
            "http://protect.example.com".into(),
        );
        assert!(Config::from_map(&vars).is_err());
    }

    #[test]
    fn http_toward_loopback_is_allowed_for_testing() {
        let mut vars = base_vars();
        vars.remove("PROTECT_BASE_URL");
        vars.remove("PROTECT_WEBHOOK_ID");
        vars.insert(
            "PROTECT_WEBHOOK_URL".into(),
            "http://127.0.0.1:9443/hook/x".into(),
        );
        assert!(Config::from_map(&vars).is_ok());
    }

    #[test]
    fn invalid_scheme_is_rejected() {
        let mut vars = base_vars();
        vars.insert("HIKVISION_SCHEME".into(), "ftp".into());
        assert!(Config::from_map(&vars).is_err());
    }

    #[test]
    fn zero_realert_disables_realerting() {
        let mut vars = base_vars();
        vars.insert("FIRE_REALERT_SECONDS".into(), "0".into());
        let cfg = Config::from_map(&vars).unwrap();
        assert_eq!(cfg.realert, None);
    }

    #[test]
    fn zero_probe_interval_disables_the_probe() {
        let mut vars = base_vars();
        vars.insert("PROTECT_PROBE_SECONDS".into(), "0".into());
        let cfg = Config::from_map(&vars).unwrap();
        assert_eq!(cfg.probe_interval, None);
    }

    #[test]
    fn zero_webhook_attempts_is_rejected() {
        let mut vars = base_vars();
        vars.insert("WEBHOOK_ATTEMPTS".into(), "0".into());
        assert!(Config::from_map(&vars).is_err());
    }

    #[test]
    fn api_key_with_control_characters_is_rejected() {
        let mut vars = base_vars();
        vars.insert("PROTECT_API_KEY".into(), "bad\nkey".into());
        assert!(Config::from_map(&vars).is_err());
    }

    #[test]
    fn custom_fire_event_types_replace_defaults() {
        let mut vars = base_vars();
        vars.insert(
            "FIRE_EVENT_TYPES".into(),
            "thermalFire, smokeDetection".into(),
        );
        let cfg = Config::from_map(&vars).unwrap();
        assert!(cfg.fire_matcher.matches("ThermalFire"));
        assert!(cfg.fire_matcher.matches(" smokedetection "));
        assert!(!cfg.fire_matcher.matches("fireDetection"));
    }

    #[test]
    fn default_fire_matcher_covers_known_hikvision_types() {
        let matcher = FireMatcher::default();
        assert!(matcher.matches("fireDetection"));
        assert!(matcher.matches("FIREALARM"));
        assert!(matcher.matches("fire_detection"));
        assert!(!matcher.matches("videoloss"));
    }

    #[test]
    fn hikvision_host_rejects_userinfo_paths_and_queries() {
        for bad in [
            "user:pass@192.0.2.10",
            "192.0.2.10/some/path",
            "192.0.2.10?x=1",
            "192.0.2.10#frag",
            "host name",
        ] {
            let mut vars = base_vars();
            vars.insert("HIKVISION_HOST".into(), bad.into());
            assert!(Config::from_map(&vars).is_err(), "must reject {bad:?}");
        }
        // host:port and bracketed IPv6 remain valid.
        for good in ["192.0.2.10:8080", "[fd00::1]:80", "camera.internal"] {
            let mut vars = base_vars();
            vars.insert("HIKVISION_HOST".into(), good.into());
            assert!(Config::from_map(&vars).is_ok(), "must accept {good:?}");
        }
    }

    #[test]
    fn zero_valued_timeouts_and_windows_are_rejected() {
        for name in [
            "STREAM_IDLE_TIMEOUT_SECONDS",
            "FIRE_COOLDOWN_SECONDS",
            "FIRE_ACTIVE_TTL_SECONDS",
            "WEBHOOK_TIMEOUT_SECONDS",
        ] {
            let mut vars = base_vars();
            vars.insert(name.into(), "0".into());
            let err = format!("{:#}", Config::from_map(&vars).unwrap_err());
            assert!(err.contains(name), "{name}: err={err}");
        }
    }

    #[test]
    fn debug_format_never_prints_secrets() {
        let mut vars = base_vars();
        vars.insert("HIKVISION_PASS".into(), "super-secret-pw".into());
        vars.insert("PROTECT_API_KEY".into(), "super-secret-key".into());
        vars.insert("PROTECT_WEBHOOK_ID".into(), "secret-hook-id".into());
        let cfg = Config::from_map(&vars).unwrap();
        let dump = format!("{cfg:?}");
        assert!(!dump.contains("super-secret-pw"), "dump={dump}");
        assert!(!dump.contains("super-secret-key"), "dump={dump}");
        assert!(!dump.contains("secret-hook-id"), "dump={dump}");
    }

    #[test]
    fn webhook_id_alphabet_is_restricted() {
        for bad in ["../../secret", "a/b", "id with space", "id%2e%2e"] {
            let mut vars = base_vars();
            vars.insert("PROTECT_WEBHOOK_ID".into(), bad.into());
            assert!(Config::from_map(&vars).is_err(), "must reject {bad:?}");
        }
        let mut vars = base_vars();
        vars.insert("PROTECT_WEBHOOK_ID".into(), "aB3-_x".into());
        assert!(Config::from_map(&vars).is_ok());
    }

    #[test]
    fn reconnect_ceiling_is_capped() {
        let mut vars = base_vars();
        vars.insert("RECONNECT_MAX_SECONDS".into(), "86400".into());
        assert!(Config::from_map(&vars).is_err());
    }

    #[test]
    fn reconnect_bounds_are_validated() {
        let mut vars = base_vars();
        vars.insert("RECONNECT_INITIAL_SECONDS".into(), "60".into());
        vars.insert("RECONNECT_MAX_SECONDS".into(), "5".into());
        assert!(Config::from_map(&vars).is_err());
    }
}
