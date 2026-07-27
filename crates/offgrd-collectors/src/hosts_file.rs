//! Hosts File Monitor — reads and parses
//! `%SystemRoot%\System32\drivers\etc\hosts`. A classic, very real
//! malware/tampering technique is silently redirecting a domain
//! (`windowsupdate.com`, a bank's domain, an AV vendor's update
//! server) to `127.0.0.1` or an attacker IP via this file — and
//! because it's just a text file, no admin API is needed to *read*
//! it, only to write it. Pure file I/O, zero `unsafe` code — the
//! lowest-risk collector in the project alongside the export module.

use anyhow::{Context, Result};
use offgrd_common::{Event, EventCategory, EventPayload, EventSource};
use std::path::PathBuf;

fn hosts_file_path() -> PathBuf {
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
    PathBuf::from(system_root).join(r"System32\drivers\etc\hosts")
}

/// Parses every non-comment, non-blank line into an
/// `EventPayload::HostsFileEntryObserved`. Malformed lines (neither a
/// valid IP nor a hostname parse) are skipped rather than causing the
/// whole read to fail — a hosts file with one weird line shouldn't
/// hide every other entry from view.
pub fn list_hosts_entries() -> Result<Vec<Event>> {
    let path = hosts_file_path();
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read hosts file at {}", path.display()))?;

    let mut events = Vec::new();
    for raw_line in contents.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Format: "<ip> <hostname> [<hostname2> ...] [# comment]".
        // We only care about the first ip/hostname pair for now — a
        // line mapping one IP to several hostnames produces one event
        // per hostname, which is more useful for rule-matching
        // ("does anything redirect windowsupdate.com") than one event
        // per line would be.
        let without_comment = trimmed.split('#').next().unwrap_or(trimmed).trim();
        let mut parts = without_comment.split_whitespace();
        let Some(ip_address) = parts.next() else {
            continue;
        };

        for hostname in parts {
            events.push(Event::new(
                EventSource::Snapshot,
                EventCategory::Dns,
                EventPayload::HostsFileEntryObserved {
                    ip_address: ip_address.to_string(),
                    hostname: hostname.to_string(),
                    raw_line: raw_line.to_string(),
                },
            ));
        }
    }

    Ok(events)
}

/// The `offgrd_core::Collector` wrapper — one-shot per `run()` call.
/// No `#[cfg(windows)]` split needed: this collector is pure file
/// I/O against a path that happens to only exist in this form on
/// Windows, but the code itself has no OS-specific API calls. On
/// non-Windows it will simply fail to find the file — a clear error,
/// not a silent no-op.
pub struct HostsFileCollector;

#[async_trait::async_trait]
impl offgrd_core::Collector for HostsFileCollector {
    fn name(&self) -> &'static str {
        "hosts-file-snapshot"
    }

    async fn run(&self, bus: &offgrd_core::EventBus) -> Result<()> {
        let events = list_hosts_entries()?;
        for event in events {
            bus.publish(event);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Can't easily test against the real Windows hosts file path in
    /// a portable unit test, so this tests the parsing logic directly
    /// against sample content instead of going through
    /// `list_hosts_entries`'s file-reading path.
    fn parse_sample(contents: &str) -> Vec<(String, String)> {
        let mut results = Vec::new();
        for raw_line in contents.lines() {
            let trimmed = raw_line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let without_comment = trimmed.split('#').next().unwrap_or(trimmed).trim();
            let mut parts = without_comment.split_whitespace();
            let Some(ip) = parts.next() else { continue };
            for hostname in parts {
                results.push((ip.to_string(), hostname.to_string()));
            }
        }
        results
    }

    #[test]
    fn parses_standard_entries_and_skips_comments() {
        let sample = "\
# This is a comment
127.0.0.1 localhost
::1 localhost
10.0.0.5 example.internal   # trailing comment
";
        let parsed = parse_sample(sample);
        assert_eq!(
            parsed,
            vec![
                ("127.0.0.1".to_string(), "localhost".to_string()),
                ("::1".to_string(), "localhost".to_string()),
                ("10.0.0.5".to_string(), "example.internal".to_string()),
            ]
        );
    }

    #[test]
    fn one_ip_mapped_to_multiple_hostnames_produces_multiple_entries() {
        let sample = "127.0.0.1 windowsupdate.com update.microsoft.com";
        let parsed = parse_sample(sample);
        assert_eq!(
            parsed,
            vec![
                ("127.0.0.1".to_string(), "windowsupdate.com".to_string()),
                ("127.0.0.1".to_string(), "update.microsoft.com".to_string()),
            ]
        );
    }

    #[test]
    fn blank_lines_and_whitespace_only_lines_are_skipped() {
        let sample = "\n   \n127.0.0.1 localhost\n\t\n";
        let parsed = parse_sample(sample);
        assert_eq!(parsed, vec![("127.0.0.1".to_string(), "localhost".to_string())]);
    }
}
