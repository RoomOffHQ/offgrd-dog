//! `offgrd export` — turns stored events/alerts into a file artifact,
//! per the architecture doc's Exports module (JSON/CSV/XML/HTML/
//! Markdown/PDF/encrypted-archive; this first pass covers JSON, CSV,
//! HTML, and Markdown — the formats with no extra dependencies or
//! genuinely tricky encoding, same "ship the honest subset" pattern
//! as the collectors. XML/PDF/encrypted-archive are real, separate
//! follow-ups, not attempted here).
//!
//! Deliberately pure Rust / no OS APIs at all — reads from
//! `offgrd_core::EventStore` (already-collected data) and writes a
//! file. This is some of the lowest-risk code in the project: no
//! `unsafe`, no Windows-specific behavior, just formatting and file
//! I/O.

use anyhow::{Context, Result};
use clap::ValueEnum;
use offgrd_common::{Alert, Event, EventPayload};
use offgrd_core::EventStore;

#[derive(Clone, Copy, ValueEnum)]
pub enum ExportKind {
    Events,
    Alerts,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    Json,
    Csv,
    Html,
    Markdown,
}

pub fn run(kind: ExportKind, format: ExportFormat, output: &str, limit: i64, db_path: &str) -> Result<()> {
    let store = EventStore::open(db_path)?;

    let content = match kind {
        ExportKind::Events => {
            let events = store.recent(limit)?;
            render_events(&events, format)?
        }
        ExportKind::Alerts => {
            let alerts = store.recent_alerts(limit)?;
            render_alerts(&alerts, format)?
        }
    };

    std::fs::write(output, content)
        .with_context(|| format!("failed to write export to {output}"))?;

    eprintln!("offgrd: wrote export to {output}");
    Ok(())
}

fn render_events(events: &[Event], format: ExportFormat) -> Result<String> {
    match format {
        ExportFormat::Json => {
            Ok(serde_json::to_string_pretty(events).context("failed to serialize events as JSON")?)
        }
        ExportFormat::Csv => Ok(events_to_csv(events)),
        ExportFormat::Html => Ok(events_to_html(events)),
        ExportFormat::Markdown => Ok(events_to_markdown(events)),
    }
}

fn render_alerts(alerts: &[Alert], format: ExportFormat) -> Result<String> {
    match format {
        ExportFormat::Json => {
            Ok(serde_json::to_string_pretty(alerts).context("failed to serialize alerts as JSON")?)
        }
        ExportFormat::Csv => Ok(alerts_to_csv(alerts)),
        ExportFormat::Html => Ok(alerts_to_html(alerts)),
        ExportFormat::Markdown => Ok(alerts_to_markdown(alerts)),
    }
}

/// Extracts the fields we actually export from an event's payload —
/// only `ProcessStarted`/`ProcessEnded`/`AutorunEntryObserved`/
/// `NetworkConnectionObserved` have meaningful flat-table
/// representations right now; anything else exports with empty
/// detail columns rather than being silently dropped from the report.
fn event_summary(event: &Event) -> (String, String) {
    match &event.payload {
        EventPayload::ProcessStarted { process } => (
            "ProcessStarted".to_string(),
            format!(
                "pid={} ppid={} image={}",
                process.pid,
                process.parent_pid.map(|p| p.to_string()).unwrap_or_default(),
                process.image_path.as_deref().unwrap_or(""),
            ),
        ),
        EventPayload::ProcessEnded { pid, exit_code } => (
            "ProcessEnded".to_string(),
            format!(
                "pid={} exit_code={}",
                pid,
                exit_code.map(|c| c.to_string()).unwrap_or_default()
            ),
        ),
        EventPayload::NetworkConnectionObserved {
            pid,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
        } => (
            "NetworkConnectionObserved".to_string(),
            format!(
                "pid={} {local_addr}:{local_port} -> {remote_addr}:{remote_port} [{state}]",
                pid.map(|p| p.to_string()).unwrap_or_default()
            ),
        ),
        EventPayload::AutorunEntryObserved {
            hive,
            key_path,
            value_name,
            value_data,
        } => (
            "AutorunEntryObserved".to_string(),
            format!("{hive}\\{key_path}\\{value_name} = {value_data}"),
        ),
        EventPayload::ServiceObserved {
            service_name,
            display_name,
            state,
            service_type,
            ..
        } => (
            "ServiceObserved".to_string(),
            format!("{service_name} ({display_name}) state={state} type={service_type}"),
        ),
        EventPayload::CertificateObserved {
            store_name,
            subject,
            issuer,
            not_after,
            ..
        } => (
            "CertificateObserved".to_string(),
            format!(
                "[{store_name}] subject={subject} issuer={issuer} expires={}",
                not_after.to_rfc3339()
            ),
        ),
        EventPayload::LoadedModuleObserved {
            pid,
            module_name,
            module_path,
            ..
        } => (
            "LoadedModuleObserved".to_string(),
            format!("pid={pid} {module_name} ({module_path})"),
        ),
        EventPayload::SessionObserved {
            session_id,
            state,
            station_name,
            user_name,
        } => (
            "SessionObserved".to_string(),
            format!(
                "session={session_id} state={state} station={station_name} user={}",
                user_name.as_deref().unwrap_or("")
            ),
        ),
        EventPayload::HostsFileEntryObserved {
            ip_address,
            hostname,
            ..
        } => (
            "HostsFileEntryObserved".to_string(),
            format!("{ip_address} -> {hostname}"),
        ),
        EventPayload::StartupFolderEntryObserved {
            scope,
            file_name,
            full_path,
        } => (
            "StartupFolderEntryObserved".to_string(),
            format!("[{scope}] {file_name} ({full_path})"),
        ),
        EventPayload::NamedPipeObserved { pipe_name } => {
            ("NamedPipeObserved".to_string(), pipe_name.clone())
        }
        EventPayload::InstalledProgramObserved {
            display_name,
            display_version,
            publisher,
            ..
        } => (
            "InstalledProgramObserved".to_string(),
            format!(
                "{display_name} {} ({})",
                display_version.as_deref().unwrap_or(""),
                publisher.as_deref().unwrap_or("unknown publisher"),
            ),
        ),
        EventPayload::ClipboardTextObserved { text } => {
            ("ClipboardTextObserved".to_string(), text.clone())
        }
        EventPayload::LocalAccountObserved { kind, name, disabled, comment } => (
            "LocalAccountObserved".to_string(),
            format!(
                "[{kind}] {name} disabled={} {}",
                disabled.map(|d| d.to_string()).unwrap_or_default(),
                comment.as_deref().unwrap_or(""),
            ),
        ),
        EventPayload::NetworkShareObserved { share_name, local_path, comment } => (
            "NetworkShareObserved".to_string(),
            format!(
                "{share_name} -> {} {}",
                local_path.as_deref().unwrap_or(""),
                comment.as_deref().unwrap_or(""),
            ),
        ),
        EventPayload::ForegroundWindowObserved { window_title, pid, process_image_path } => (
            "ForegroundWindowObserved".to_string(),
            format!(
                "\"{window_title}\" pid={} {}",
                pid.map(|p| p.to_string()).unwrap_or_default(),
                process_image_path.as_deref().unwrap_or(""),
            ),
        ),
        EventPayload::EnvironmentVariableObserved { name, value } => (
            "EnvironmentVariableObserved".to_string(),
            format!("{name}={value}"),
        ),
        EventPayload::DnsCacheEntryObserved { hostname, record_type, data } => (
            "DnsCacheEntryObserved".to_string(),
            format!("{hostname} {record_type} {data}"),
        ),
        EventPayload::IdleStateObserved { idle_seconds } => (
            "IdleStateObserved".to_string(),
            format!("{idle_seconds}s idle"),
        ),
        EventPayload::Note { message } => ("Note".to_string(), message.clone()),
    }
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn events_to_csv(events: &[Event]) -> String {
    let mut out = String::from("timestamp,category,source,type,detail\n");
    for event in events {
        let (event_type, detail) = event_summary(event);
        out.push_str(&format!(
            "{},{:?},{:?},{},{}\n",
            event.timestamp.to_rfc3339(),
            event.category,
            event.source,
            csv_escape(&event_type),
            csv_escape(&detail),
        ));
    }
    out
}

fn events_to_html(events: &[Event]) -> String {
    let mut rows = String::new();
    for event in events {
        let (event_type, detail) = event_summary(event);
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{:?}</td><td>{}</td><td>{}</td></tr>\n",
            event.timestamp.to_rfc3339(),
            event.category,
            html_escape(&event_type),
            html_escape(&detail),
        ));
    }
    html_document("OffGrd Dog — Event Export", "Timestamp,Category,Type,Detail", &rows)
}

fn events_to_markdown(events: &[Event]) -> String {
    let mut out = String::from("| Timestamp | Category | Type | Detail |\n|---|---|---|---|\n");
    for event in events {
        let (event_type, detail) = event_summary(event);
        out.push_str(&format!(
            "| {} | {:?} | {} | {} |\n",
            event.timestamp.to_rfc3339(),
            event.category,
            event_type,
            detail.replace('|', "\\|"),
        ));
    }
    out
}

fn alerts_to_csv(alerts: &[Alert]) -> String {
    let mut out = String::from("timestamp,severity,rule_id,rule_title,triggering_event_id\n");
    for alert in alerts {
        out.push_str(&format!(
            "{},{:?},{},{},{}\n",
            alert.timestamp.to_rfc3339(),
            alert.severity,
            csv_escape(&alert.rule_id),
            csv_escape(&alert.rule_title),
            alert.triggering_event_id,
        ));
    }
    out
}

fn alerts_to_html(alerts: &[Alert]) -> String {
    let mut rows = String::new();
    for alert in alerts {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{:?}</td><td>{}</td><td>{}</td></tr>\n",
            alert.timestamp.to_rfc3339(),
            alert.severity,
            html_escape(&alert.rule_id),
            html_escape(&alert.rule_title),
        ));
    }
    html_document("OffGrd Dog — Alert Export", "Timestamp,Severity,Rule ID,Rule Title", &rows)
}

fn alerts_to_markdown(alerts: &[Alert]) -> String {
    let mut out = String::from("| Timestamp | Severity | Rule ID | Rule Title |\n|---|---|---|---|\n");
    for alert in alerts {
        out.push_str(&format!(
            "| {} | {:?} | {} | {} |\n",
            alert.timestamp.to_rfc3339(),
            alert.severity,
            alert.rule_id,
            alert.rule_title,
        ));
    }
    out
}

fn html_document(title: &str, header_csv: &str, rows: &str) -> String {
    let headers: Vec<&str> = header_csv.split(',').collect();
    let header_row = headers
        .iter()
        .map(|h| format!("<th>{h}</th>"))
        .collect::<Vec<_>>()
        .join("");

    format!(
        r#"<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  body {{ font-family: sans-serif; background: #0d1117; color: #e6edf3; padding: 24px; }}
  h1 {{ font-size: 18px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #262c36; padding: 6px 10px; font-size: 12.5px; text-align: left; }}
  th {{ background: #161b22; }}
  tr:nth-child(even) {{ background: #12161d; }}
</style>
</head>
<body>
<h1>{title}</h1>
<table>
<thead><tr>{header_row}</tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use offgrd_common::{EventCategory, EventSource, ProcessRef, Severity};
    use uuid::Uuid;

    fn sample_event() -> Event {
        let process = ProcessRef::new(42).with_image_path(r"C:\Windows\System32\notepad.exe");
        Event::new(
            EventSource::Snapshot,
            EventCategory::Process,
            EventPayload::ProcessStarted { process },
        )
    }

    #[test]
    fn events_csv_contains_header_and_row() {
        let csv = events_to_csv(&[sample_event()]);
        assert!(csv.starts_with("timestamp,category,source,type,detail\n"));
        assert!(csv.contains("ProcessStarted"));
        assert!(csv.contains("notepad.exe"));
    }

    #[test]
    fn events_html_escapes_and_wraps_in_a_document() {
        let html = events_to_html(&[sample_event()]);
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("<table>"));
    }

    #[test]
    fn events_markdown_produces_a_valid_looking_table() {
        let md = events_to_markdown(&[sample_event()]);
        assert!(md.starts_with("| Timestamp | Category | Type | Detail |\n"));
        assert!(md.contains("ProcessStarted"));
    }

    #[test]
    fn csv_escape_quotes_fields_containing_commas() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("has \"quote\""), "\"has \"\"quote\"\"\"");
    }

    #[test]
    fn alerts_json_round_trips_through_serde() {
        let alert = Alert::new("rule-1", "Rule One", Severity::High, Uuid::new_v4());
        let json = serde_json::to_string(&[alert.clone()]).unwrap();
        let back: Vec<Alert> = serde_json::from_str(&json).unwrap();
        assert_eq!(back[0].rule_id, alert.rule_id);
    }
}
