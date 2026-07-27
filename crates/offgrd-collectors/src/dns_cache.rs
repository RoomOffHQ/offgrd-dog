//! DNS Cache Viewer — the local resolver cache (what hostnames this
//! machine has recently resolved, and to what).
//!
//! **Deliberate pragmatic tradeoff**: the "real" API for this is
//! `DnsGetCacheDataTable`, which is undocumented, unstable across
//! Windows versions, and exactly the kind of blind-guess `unsafe`
//! code this project has been trying to avoid (see the ETW
//! collector's caveats for what happens when that goes wrong). This
//! collector instead shells out to `ipconfig /displaydns` — a stable,
//! documented, supported command — and parses its text output. Less
//! elegant, considerably more robust. No `unsafe` code.

use anyhow::{Context, Result};
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};
use std::process::Command;

pub fn list_dns_cache_entries() -> Result<Vec<Event>> {
    let output = Command::new("ipconfig")
        .arg("/displaydns")
        .output()
        .context("failed to run ipconfig /displaydns")?;

    if !output.status.success() {
        anyhow::bail!(
            "ipconfig /displaydns exited with status {}",
            output.status
        );
    }

    // ipconfig's output encoding varies by system locale/codepage;
    // lossy UTF-8 conversion is the pragmatic choice here since we
    // only need to parse ASCII field names and hostnames/IPs out of
    // it, not preserve every possible character exactly.
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_displaydns(&text))
}

/// Parses `ipconfig /displaydns`'s block-structured text output. Each
/// entry looks roughly like:
/// ```text
///     example.com
///     ----------------------------------------
///     Record Name . . . . . : example.com
///     Record Type . . . . . : 1
///     Time To Live  . . . . : 45
///     Data Length . . . . . : 4
///     Section . . . . . . . : Answer
///     A (Host) Record . . . : 93.184.216.34
/// ```
/// This parser is deliberately lenient: it looks for "Record Name",
/// then the next line containing a recognizable record-type label
/// ("A (Host) Record", "AAAA (Host) Record", "CNAME Record", etc.)
/// followed by its data, rather than assuming an exact fixed line
/// count per block — `ipconfig`'s output format isn't a documented
/// contract, so brittleness here should fail gracefully (fewer
/// parsed entries), not panic.
fn parse_displaydns(text: &str) -> Vec<Event> {
    let mut events = Vec::new();
    let mut current_hostname: Option<String> = None;

    for line in text.lines() {
        if let Some(name) = extract_field(line, "Record Name") {
            current_hostname = Some(name);
            continue;
        }

        let Some(hostname) = &current_hostname else {
            continue;
        };

        for (label, record_type) in [
            ("A (Host) Record", "A"),
            ("AAAA (Host) Record", "AAAA"),
            ("CNAME Record", "CNAME"),
            ("PTR Record", "PTR"),
        ] {
            if let Some(data) = extract_field(line, label) {
                events.push(Event::new(
                    EventSource::Snapshot,
                    EventCategory::Dns,
                    EventPayload::DnsCacheEntryObserved {
                        hostname: hostname.clone(),
                        record_type: record_type.to_string(),
                        data,
                    },
                ));
            }
        }
    }

    events
}

/// `ipconfig`'s fields look like "Label . . . . . : value" (a
/// variable number of ". " separators padding to a column, then a
/// colon). This matches on the label prefix and returns whatever
/// comes after the first ':' on that line, trimmed.
fn extract_field(line: &str, label: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if !trimmed.starts_with(label) {
        return None;
    }
    let value = trimmed.splitn(2, ':').nth(1)?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// The `offgrd_core::Collector` wrapper — one-shot per `run()` call.
pub struct DnsCacheCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for DnsCacheCollector {
    fn name(&self) -> &'static str {
        "dns-cache-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        let events = list_dns_cache_entries()?;
        for event in events {
            bus.publish(event);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_record_block() {
        let sample = "
Windows IP Configuration

    example.com
    ----------------------------------------
    Record Name . . . . . : example.com
    Record Type . . . . . : 1
    Time To Live  . . . . : 45
    Data Length . . . . . : 4
    Section . . . . . . . : Answer
    A (Host) Record . . . : 93.184.216.34

";
        let events = parse_displaydns(sample);
        assert_eq!(events.len(), 1);
        match &events[0].payload {
            offgrd_common::EventPayload::DnsCacheEntryObserved { hostname, record_type, data } => {
                assert_eq!(hostname, "example.com");
                assert_eq!(record_type, "A");
                assert_eq!(data, "93.184.216.34");
            }
            other => panic!("unexpected payload: {other:?}"),
        }
    }

    #[test]
    fn handles_multiple_entries_and_ignores_unrelated_lines() {
        let sample = "
    one.example.com
    ----------------------------------------
    Record Name . . . . . : one.example.com
    Record Type . . . . . : 1
    A (Host) Record . . . : 10.0.0.1

    two.example.com
    ----------------------------------------
    Record Name . . . . . : two.example.com
    Record Type . . . . . : 28
    AAAA (Host) Record . . : ::1
";
        let events = parse_displaydns(sample);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn empty_input_produces_no_entries() {
        assert!(parse_displaydns("").is_empty());
    }
}
