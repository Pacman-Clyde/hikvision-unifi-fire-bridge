//! Structural parsing of a single `EventNotificationAlert` XML document.
//!
//! Hikvision firmwares vary: namespaces may or may not be present, element
//! prefixes differ, and values carry stray whitespace. Matching is therefore
//! done on namespace-local element names against decoded text content — never
//! on substrings of the raw document.

use anyhow::Result;
use quick_xml::Reader;
use quick_xml::events::Event;

/// Normalised `eventState` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventState {
    Active,
    Inactive,
    /// The document had an `eventType` but no `eventState` element. Some
    /// firmwares emit presence-based events where the document existing *is*
    /// the alarm — the processor treats a fire-matching type without state as
    /// active (fail toward alert, never silent drop).
    Missing,
    Unknown(String),
}

impl EventState {
    fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "active" | "true" | "1" => Self::Active,
            "inactive" | "false" | "0" => Self::Inactive,
            other => Self::Unknown(other.to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CameraEvent {
    pub event_type: String,
    pub state: EventState,
    /// `channelID` (or `dynChannelID`) when present; identifies the source on
    /// multi-channel devices.
    pub channel: Option<String>,
}

/// Parse one complete XML document. Returns `Ok(None)` when the document is
/// well-formed but is not an event notification (no `eventType` at all). A
/// missing `eventState` yields [`EventState::Missing`] rather than dropping
/// the document — the caller decides how to fail safe.
pub fn parse_event(xml: &[u8]) -> Result<Option<CameraEvent>> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(true);

    let mut current: Vec<u8> = Vec::new();
    let mut event_type: Option<String> = None;
    let mut event_state: Option<String> = None;
    let mut channel: Option<String> = None;

    loop {
        match reader.read_event()? {
            Event::Start(e) => current = local_name(e.name().as_ref()).to_vec(),
            Event::Text(t) => {
                let value = t.decode()?.into_owned();
                assign(
                    &current,
                    value,
                    &mut event_type,
                    &mut event_state,
                    &mut channel,
                );
            }
            Event::CData(t) => {
                let value = String::from_utf8_lossy(&t.into_inner()).into_owned();
                assign(
                    &current,
                    value,
                    &mut event_type,
                    &mut event_state,
                    &mut channel,
                );
            }
            Event::End(_) => current.clear(),
            Event::Eof => break,
            _ => {}
        }
    }

    Ok(event_type.map(|event_type| CameraEvent {
        event_type,
        state: event_state
            .map(|s| EventState::parse(&s))
            .unwrap_or(EventState::Missing),
        channel,
    }))
}

fn assign(
    element: &[u8],
    value: String,
    event_type: &mut Option<String>,
    event_state: &mut Option<String>,
    channel: &mut Option<String>,
) {
    // First occurrence wins: top-level fields precede any nested repetition.
    match element {
        b"eventType" if event_type.is_none() => *event_type = Some(value),
        b"eventState" if event_state.is_none() => *event_state = Some(value),
        b"channelID" | b"dynChannelID" if channel.is_none() => {
            *channel = Some(sanitize_channel(&value))
        }
        _ => {}
    }
}

/// The channel value is attacker-influenced (a compromised camera chooses
/// it) and flows into structured logs and the webhook payload. Strip control
/// characters (log forging via embedded newlines/escapes) and cap the length.
fn sanitize_channel(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect()
}

/// Strip any namespace prefix: `ns:eventType` -> `eventType`.
fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|&b| b == b':') {
        Some(idx) => &name[idx + 1..],
        None => name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_fire_event() {
        let event = parse_event(
            br#"<EventNotificationAlert>
                <eventType>fireDetection</eventType>
                <eventState>active</eventState>
                <channelID>1</channelID>
            </EventNotificationAlert>"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(event.event_type, "fireDetection");
        assert_eq!(event.state, EventState::Active);
        assert_eq!(event.channel.as_deref(), Some("1"));
    }

    #[test]
    fn parses_namespaced_document_with_attributes() {
        let event = parse_event(
            br#"<EventNotificationAlert version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
                <eventType>fireDetection</eventType>
                <eventState>active</eventState>
                <channelID>1</channelID>
            </EventNotificationAlert>"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(event.event_type, "fireDetection");
        assert_eq!(event.state, EventState::Active);
    }

    #[test]
    fn parses_prefixed_element_names() {
        let event = parse_event(
            br#"<hik:EventNotificationAlert xmlns:hik="http://example">
                <hik:eventType>fireDetection</hik:eventType>
                <hik:eventState>inactive</hik:eventState>
            </hik:EventNotificationAlert>"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(event.event_type, "fireDetection");
        assert_eq!(event.state, EventState::Inactive);
    }

    #[test]
    fn heartbeat_videoloss_parses_as_non_fire_event() {
        let event = parse_event(
            br#"<EventNotificationAlert>
                <eventType>videoloss</eventType>
                <eventState>inactive</eventState>
                <channelID>1</channelID>
            </EventNotificationAlert>"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(event.event_type, "videoloss");
        assert_eq!(event.state, EventState::Inactive);
    }

    #[test]
    fn state_normalisation_accepts_firmware_variants() {
        for raw in ["active", " Active ", "TRUE", "1"] {
            assert_eq!(EventState::parse(raw), EventState::Active, "raw={raw:?}");
        }
        for raw in ["inactive", "False", "0"] {
            assert_eq!(EventState::parse(raw), EventState::Inactive, "raw={raw:?}");
        }
        assert_eq!(
            EventState::parse("notSupport"),
            EventState::Unknown("notsupport".into())
        );
    }

    #[test]
    fn document_without_event_fields_is_not_an_event() {
        let parsed =
            parse_event(b"<EventNotificationAlert><foo>1</foo></EventNotificationAlert>").unwrap();
        assert!(parsed.is_none());
    }

    #[test]
    fn event_type_without_state_yields_missing_state_not_a_drop() {
        // Presence-based events must not vanish: the processor fails toward
        // alert for fire-matching types.
        let event = parse_event(
            br#"<EventNotificationAlert>
                <eventType>fireDetection</eventType>
                <channelID>2</channelID>
            </EventNotificationAlert>"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(event.event_type, "fireDetection");
        assert_eq!(event.state, EventState::Missing);
        assert_eq!(event.channel.as_deref(), Some("2"));
    }

    #[test]
    fn malformed_xml_is_an_error_not_a_panic() {
        assert!(parse_event(b"<EventNotificationAlert><event").is_err());
    }

    #[test]
    fn channel_is_sanitised_against_log_forging() {
        let event = parse_event(
            b"<EventNotificationAlert>\
                <eventType>fireDetection</eventType>\
                <eventState>active</eventState>\
                <channelID>1\x1b[31m\nFAKE LOG LINE</channelID>\
            </EventNotificationAlert>",
        )
        .unwrap()
        .unwrap();
        let channel = event.channel.unwrap();
        assert!(!channel.contains('\n'), "channel={channel:?}");
        assert!(!channel.contains('\x1b'), "channel={channel:?}");
        assert!(channel.starts_with('1'));
        assert!(channel.len() <= 64);
    }

    #[test]
    fn nested_repeated_elements_do_not_override_first_values() {
        let event = parse_event(
            br#"<EventNotificationAlert>
                <eventType>fireDetection</eventType>
                <eventState>active</eventState>
                <DetectionRegionList>
                    <eventType>ignored</eventType>
                </DetectionRegionList>
            </EventNotificationAlert>"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(event.event_type, "fireDetection");
    }
}
