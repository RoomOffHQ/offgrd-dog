//! SQLite-backed persistence for `Event`s.
//!
//! This is the foundation for the future timeline module: without it,
//! OffGrd Dog can only ever show you what's happening *right now*.
//! `EventStore` gives every event a durable home so the UI/CLI can
//! later query history, not just live snapshots.
//!
//! Design choices, deliberately kept simple for this milestone:
//! - The whole `Event` is stored as a JSON blob (`payload_json`), plus
//!   a handful of denormalized columns (`timestamp`, `category`,
//!   `source`, `severity`) that we'll actually want to filter/sort by
//!   in the timeline UI later. This avoids a rigid per-category SQL
//!   schema while still keeping the common queries (by time range, by
//!   category) fast via indexes.
//! - `rusqlite` with the `bundled` feature so no contributor needs a
//!   system SQLite install to build the project.
//! - A single `std::sync::Mutex<Connection>`, not a connection pool.
//!   SQLite serializes writes internally anyway, and this crate has no
//!   throughput requirements yet that would justify the complexity of
//!   a pool (e.g. r2d2) — revisit once a high-volume collector
//!   (filesystem, network) is actually feeding this.

use anyhow::{Context, Result};
use offgrd_common::{Event, EventCategory, EventSource, Severity};
use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;

pub struct EventStore {
    conn: Mutex<Connection>,
}

impl EventStore {
    /// Opens (creating if needed) a SQLite database file on disk and
    /// ensures the schema exists.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path).context("failed to open event store database")?;
        Self::from_connection(conn)
    }

    /// In-memory database — used by tests, and potentially useful for
    /// a future "don't persist anything to disk" privacy mode.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().context("failed to open in-memory event store")?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS events (
                id            TEXT PRIMARY KEY,
                timestamp_utc TEXT NOT NULL,
                category      TEXT NOT NULL,
                source        TEXT NOT NULL,
                severity      TEXT,
                payload_json  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_utc);
            CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);
            ",
        )
        .context("failed to initialize event store schema")?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Persists a single event. Idempotent on `id`: re-inserting the
    /// same event id is a no-op rather than an error, since a
    /// collector retry or a bus re-delivery after a lag shouldn't
    /// crash storage.
    pub fn insert(&self, event: &Event) -> Result<()> {
        let payload_json =
            serde_json::to_string(&event.payload).context("failed to serialize event payload")?;

        let conn = self.conn.lock().expect("event store mutex poisoned");
        conn.execute(
            "INSERT OR IGNORE INTO events (id, timestamp_utc, category, source, severity, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                event.id.to_string(),
                event.timestamp.to_rfc3339(),
                category_label(event.category),
                source_label(event.source),
                event.severity_hint.map(severity_label),
                payload_json,
            ],
        )
        .context("failed to insert event")?;

        Ok(())
    }

    /// Total number of stored events. Mostly useful for tests and
    /// diagnostics right now; will grow into real filtered counts
    /// (e.g. "events in the last hour") once the timeline UI needs it.
    pub fn count(&self) -> Result<i64> {
        let conn = self.conn.lock().expect("event store mutex poisoned");
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Returns the `limit` most recent events, newest first. Full
    /// `Event`s are reconstructed from the stored JSON blob, so this
    /// is a real round-trip (id, timestamp, category, everything),
    /// not just a summary.
    pub fn recent(&self, limit: i64) -> Result<Vec<Event>> {
        let conn = self.conn.lock().expect("event store mutex poisoned");

        let mut stmt = conn.prepare(
            "SELECT id, timestamp_utc, category, source, severity, payload_json
             FROM events ORDER BY timestamp_utc DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map([limit], |row| {
            let id: String = row.get(0)?;
            let timestamp_utc: String = row.get(1)?;
            let payload_json: String = row.get(5)?;
            Ok((id, timestamp_utc, payload_json))
        })?;

        let mut events = Vec::new();
        for row in rows {
            let (_id, _timestamp_utc, payload_json) = row?;
            // We only stored the *payload* as JSON, but `Event` needs
            // id/timestamp/source/category too. Reconstruct the full
            // Event from the denormalized columns plus the decoded
            // payload rather than assuming payload_json round-trips to
            // a whole Event (it doesn't, by construction above).
            let payload: offgrd_common::EventPayload = serde_json::from_str(&payload_json)
                .context("failed to deserialize stored event payload")?;
            events.push(reconstruct_event(&_id, &_timestamp_utc, payload, &conn)?);
        }

        Ok(events)
    }
}

/// Rebuilds a full `Event` from its denormalized columns. Kept as a
/// free function (rather than inline in `recent`) because it re-reads
/// category/source/severity for the given id — see the note in
/// `recent` about `payload_json` only covering the payload, not the
/// whole event.
fn reconstruct_event(
    id: &str,
    timestamp_utc: &str,
    payload: offgrd_common::EventPayload,
    conn: &Connection,
) -> Result<Event> {
    let (category_str, source_str, severity_str): (String, String, Option<String>) = conn
        .query_row(
            "SELECT category, source, severity FROM events WHERE id = ?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .context("failed to re-read event metadata")?;

    Ok(Event {
        id: id.parse().context("stored event id is not a valid UUID")?,
        timestamp: timestamp_utc
            .parse::<chrono::DateTime<chrono::Utc>>()
            .context("stored timestamp is not valid RFC3339")?,
        category: parse_category(&category_str)?,
        source: parse_source(&source_str)?,
        severity_hint: severity_str.map(|s| parse_severity(&s)).transpose()?,
        payload,
    })
}

fn category_label(category: EventCategory) -> &'static str {
    match category {
        EventCategory::Process => "process",
        EventCategory::Network => "network",
        EventCategory::Dns => "dns",
        EventCategory::Registry => "registry",
        EventCategory::File => "file",
        EventCategory::Persistence => "persistence",
        EventCategory::Alert => "alert",
    }
}

fn parse_category(s: &str) -> Result<EventCategory> {
    Ok(match s {
        "process" => EventCategory::Process,
        "network" => EventCategory::Network,
        "dns" => EventCategory::Dns,
        "registry" => EventCategory::Registry,
        "file" => EventCategory::File,
        "persistence" => EventCategory::Persistence,
        "alert" => EventCategory::Alert,
        other => anyhow::bail!("unknown stored event category: {other}"),
    })
}

fn source_label(source: EventSource) -> &'static str {
    match source {
        EventSource::Snapshot => "snapshot",
        EventSource::Etw => "etw",
        EventSource::Wmi => "wmi",
        EventSource::Minifilter => "minifilter",
        EventSource::RegistryNotify => "registry_notify",
        EventSource::Derived => "derived",
    }
}

fn parse_source(s: &str) -> Result<EventSource> {
    Ok(match s {
        "snapshot" => EventSource::Snapshot,
        "etw" => EventSource::Etw,
        "wmi" => EventSource::Wmi,
        "minifilter" => EventSource::Minifilter,
        "registry_notify" => EventSource::RegistryNotify,
        "derived" => EventSource::Derived,
        other => anyhow::bail!("unknown stored event source: {other}"),
    })
}

fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn parse_severity(s: &str) -> Result<Severity> {
    Ok(match s {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        other => anyhow::bail!("unknown stored event severity: {other}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use offgrd_common::{EventPayload, ProcessRef};

    fn sample_event() -> Event {
        let process = ProcessRef::new(4242).with_image_path(r"C:\Windows\System32\svchost.exe");
        Event::new(
            EventSource::Snapshot,
            EventCategory::Process,
            EventPayload::ProcessStarted { process },
        )
        .with_severity(Severity::Info)
    }

    #[test]
    fn insert_and_count() {
        let store = EventStore::open_in_memory().expect("open store");
        assert_eq!(store.count().unwrap(), 0);

        store.insert(&sample_event()).expect("insert");
        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn inserting_same_id_twice_is_idempotent() {
        let store = EventStore::open_in_memory().expect("open store");
        let event = sample_event();

        store.insert(&event).expect("first insert");
        store.insert(&event).expect("second insert (same id)");

        assert_eq!(store.count().unwrap(), 1);
    }

    #[test]
    fn recent_round_trips_full_event() {
        let store = EventStore::open_in_memory().expect("open store");
        let event = sample_event();
        store.insert(&event).expect("insert");

        let recent = store.recent(10).expect("query recent");
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].id, event.id);
        assert_eq!(recent[0].category, event.category);
        assert_eq!(recent[0].severity_hint, event.severity_hint);

        match (&recent[0].payload, &event.payload) {
            (
                EventPayload::ProcessStarted { process: a },
                EventPayload::ProcessStarted { process: b },
            ) => assert_eq!(a.pid, b.pid),
            _ => panic!("payload variant mismatch after round-trip"),
        }
    }

    #[test]
    fn opens_a_real_file_on_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("events.db");

        {
            let store = EventStore::open(&path).expect("open on-disk store");
            store.insert(&sample_event()).expect("insert");
        } // dropped, connection closed

        let reopened = EventStore::open(&path).expect("reopen on-disk store");
        assert_eq!(reopened.count().unwrap(), 1);
    }
}
