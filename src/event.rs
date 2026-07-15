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
/// well-formed but is not an event notification (no `eventType`/`eventState`).
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

    Ok(match (event_type, event_state) {
        (Some(event_type), Some(state)) => Some(CameraEvent {
            event_type,
            state: EventState::parse(&state),
            channel,
        }),
        _ => None,
    })
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
        b"channelID" | b"dynChannelID" if channel.is_none() => *channel = Some(value),
        _ => {}
    }
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
    fn malformed_xml_is_an_error_not_a_panic() {
        assert!(parse_event(b"<EventNotificationAlert><event").is_err());
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
