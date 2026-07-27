//! offgrd-cli — the very first runnable, tangible piece of OffGrd Dog.
//!
//! Scope on purpose: enumerate running processes and print them, either
//! as a table or as JSON (`Event` envelopes from offgrd-common). No
//! driver, no ETW, no admin rights required. Under the hood, `ps` now
//! runs as an `offgrd_core::Collector` publishing onto an `EventBus`
//! rather than being called directly — every future collector
//! (network, registry, filesystem, ETW-based process monitoring) will
//! plug into the same pipeline.

mod export;
mod monitor;

use anyhow::Result;
use clap::{Parser, Subcommand};
use export::{ExportFormat, ExportKind};
use offgrd_collectors::ProcessSnapshotCollector;
use offgrd_common::{Event, EventPayload};
use offgrd_core::{Collector, EventBus, EventStore};
use tokio::sync::broadcast::error::TryRecvError;

/// Default location of the event store database, relative to the
/// current working directory. A real install will move this to a
/// proper per-user data directory; kept simple and visible for now.
const DEFAULT_DB_PATH: &str = "offgrd.db";

#[derive(Parser)]
#[command(
    name = "offgrd",
    version,
    about = "OffGrd Dog CLI — Know Everything. Trust Nothing."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Emit machine-readable JSON (one Event per line) instead of a table.
    #[arg(long, global = true)]
    json: bool,

    /// Path to the SQLite event store database.
    #[arg(long, global = true, default_value = DEFAULT_DB_PATH)]
    db: String,
}

#[derive(Subcommand)]
enum Command {
    /// List currently running processes.
    Ps {
        /// Render as an indented parent -> child tree instead of a flat table.
        #[arg(long)]
        tree: bool,

        /// Persist the collected events to the event store (--db).
        #[arg(long)]
        save: bool,
    },
    /// Show previously stored events from the event store (--db).
    History {
        /// Maximum number of events to show, most recent first.
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
    /// (Windows only, EXPERIMENTAL) Watch live process start/stop
    /// events via ETW instead of polling. Runs until Ctrl+C or
    /// --seconds elapses.
    Watch {
        /// Stop automatically after this many seconds (0 = run until Ctrl+C).
        #[arg(long, default_value_t = 0)]
        seconds: u64,

        /// Also persist watched events to the event store (--db).
        #[arg(long)]
        save: bool,
    },
    /// Evaluate detection rules against events and print matches.
    Alerts {
        /// Directory containing *.yaml/*.yml rule files.
        #[arg(long, default_value = "rules")]
        rules_dir: String,

        /// Evaluate against previously stored events (--db) instead of
        /// taking a fresh process snapshot.
        #[arg(long)]
        from_history: bool,

        /// With --from-history, how many recent events to evaluate.
        #[arg(long, default_value_t = 200)]
        limit: i64,

        /// Persist matched alerts to the event store (--db).
        #[arg(long)]
        save: bool,
    },
    /// Show previously stored alerts from the event store (--db).
    AlertHistory {
        /// Maximum number of alerts to show, most recent first.
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
    /// Continuously watch for process start/stop by polling at a fixed
    /// interval (no ETW/admin rights needed — see `watch` for the
    /// higher-fidelity, still-experimental ETW-based alternative).
    /// Runs until Ctrl+C.
    Monitor {
        /// Poll interval in seconds.
        #[arg(long, default_value_t = 5)]
        interval: u64,

        /// Directory containing *.yaml/*.yml rule files.
        #[arg(long, default_value = "rules")]
        rules_dir: String,

        /// Persist observed start/stop events to the event store (--db).
        #[arg(long)]
        save_events: bool,

        /// Persist triggered alerts to the event store (--db).
        #[arg(long)]
        save_alerts: bool,
    },
    /// Lint every rule file in a directory and report which ones
    /// failed to parse, without stopping at the first bad file.
    RulesCheck {
        /// Directory containing *.yaml/*.yml rule files.
        #[arg(long, default_value = "rules")]
        rules_dir: String,
    },
    /// List active IPv4 TCP connections (Windows only).
    Net {
        /// Persist observed connections to the event store (--db).
        #[arg(long)]
        save: bool,
    },
    /// List registry Run/RunOnce autorun entries (Windows only).
    Autoruns {
        /// Persist observed entries to the event store (--db).
        #[arg(long)]
        save: bool,
    },
    /// List Windows services (Windows only).
    Services {
        /// Persist observed services to the event store (--db).
        #[arg(long)]
        save: bool,
    },
    /// List certificates in the ROOT/CA/MY system stores (Windows only).
    Certs {
        /// Persist observed certificates to the event store (--db).
        #[arg(long)]
        save: bool,
    },
    /// List loaded modules (DLLs) for every running process (Windows only).
    Modules {
        /// Persist observed modules to the event store (--db).
        #[arg(long)]
        save: bool,
    },
    /// List active console/RDP sessions (Windows only).
    Sessions {
        /// Persist observed sessions to the event store (--db).
        #[arg(long)]
        save: bool,
    },
    /// Show parsed entries from the hosts file.
    Hosts {
        /// Persist observed entries to the event store (--db).
        #[arg(long)]
        save: bool,
    },
    /// List shortcuts/executables in the Startup folders (Windows only).
    StartupItems {
        /// Persist observed entries to the event store (--db).
        #[arg(long)]
        save: bool,
    },
    /// List named pipes visible under \\.\pipe\ (Windows only).
    Pipes {
        /// Persist observed pipes to the event store (--db).
        #[arg(long)]
        save: bool,
    },
    /// List installed programs (Add/Remove Programs, Windows only).
    Programs {
        /// Persist observed programs to the event store (--db).
        #[arg(long)]
        save: bool,
    },
    /// Show the current clipboard's text content, if any (Windows
    /// only). PRIVACY-SENSITIVE: reads whatever text is currently on
    /// your clipboard.
    Clipboard {
        /// Persist the observed clipboard text to the event store (--db).
        #[arg(long)]
        save: bool,
    },
    /// List local user accounts and groups (Windows only).
    Accounts {
        #[arg(long)]
        save: bool,
    },
    /// List local network (SMB) shares (Windows only).
    Shares {
        #[arg(long)]
        save: bool,
    },
    /// Show the current foreground window, once (Windows only).
    Foreground {
        #[arg(long)]
        save: bool,
    },
    /// Show this process's environment variables.
    Env {
        #[arg(long)]
        save: bool,
    },
    /// Show the local DNS resolver cache (via `ipconfig /displaydns`).
    DnsCache {
        #[arg(long)]
        save: bool,
    },
    /// Show how long the machine has been idle (Windows only).
    Idle {
        #[arg(long)]
        save: bool,
    },
    /// Export stored events or alerts to a file (JSON, CSV, HTML, or Markdown).
    Export {
        /// What to export.
        #[arg(long, value_enum)]
        kind: ExportKind,

        /// Output format.
        #[arg(long, value_enum)]
        format: ExportFormat,

        /// Output file path.
        #[arg(long)]
        output: String,

        /// How many recent records to export, most recent first.
        #[arg(long, default_value_t = 1000)]
        limit: i64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Ps { tree, save } => run_ps(cli.json, tree, save, &cli.db).await,
        Command::History { limit } => run_history(cli.json, limit, &cli.db),
        Command::Watch { seconds, save } => run_watch(cli.json, seconds, save, &cli.db).await,
        Command::Alerts {
            rules_dir,
            from_history,
            limit,
            save,
        } => run_alerts(cli.json, &rules_dir, from_history, limit, save, &cli.db).await,
        Command::AlertHistory { limit } => run_alert_history(cli.json, limit, &cli.db),
        Command::Monitor {
            interval,
            rules_dir,
            save_events,
            save_alerts,
        } => {
            monitor::run(monitor::MonitorConfig {
                interval: std::time::Duration::from_secs(interval),
                rules_dir,
                save_events,
                save_alerts,
                db_path: cli.db,
                json: cli.json,
            })
            .await
        }
        Command::RulesCheck { rules_dir } => run_rules_check(&rules_dir),
        Command::Net { save } => run_net(cli.json, save, &cli.db).await,
        Command::Autoruns { save } => run_autoruns(cli.json, save, &cli.db).await,
        Command::Services { save } => run_services(cli.json, save, &cli.db).await,
        Command::Certs { save } => run_certs(cli.json, save, &cli.db).await,
        Command::Modules { save } => run_simple_collector(
            "modules", offgrd_collectors::ModulesCollector, cli.json, save, &cli.db,
        ).await,
        Command::Sessions { save } => run_simple_collector(
            "sessions", offgrd_collectors::SessionsCollector, cli.json, save, &cli.db,
        ).await,
        Command::Hosts { save } => run_simple_collector(
            "hosts entries", offgrd_collectors::HostsFileCollector, cli.json, save, &cli.db,
        ).await,
        Command::StartupItems { save } => run_simple_collector(
            "startup items", offgrd_collectors::StartupFolderCollector, cli.json, save, &cli.db,
        ).await,
        Command::Pipes { save } => run_simple_collector(
            "named pipes", offgrd_collectors::NamedPipesCollector, cli.json, save, &cli.db,
        ).await,
        Command::Programs { save } => run_simple_collector(
            "installed programs", offgrd_collectors::InstalledProgramsCollector, cli.json, save, &cli.db,
        ).await,
        Command::Clipboard { save } => run_simple_collector(
            "clipboard snapshot", offgrd_collectors::ClipboardCollector, cli.json, save, &cli.db,
        ).await,
        Command::Accounts { save } => run_simple_collector(
            "local accounts", offgrd_collectors::LocalAccountsCollector, cli.json, save, &cli.db,
        ).await,
        Command::Shares { save } => run_simple_collector(
            "network shares", offgrd_collectors::NetworkSharesCollector, cli.json, save, &cli.db,
        ).await,
        Command::Foreground { save } => run_simple_collector(
            "foreground window", offgrd_collectors::ForegroundWindowCollector, cli.json, save, &cli.db,
        ).await,
        Command::Env { save } => run_simple_collector(
            "environment variables", offgrd_collectors::EnvironmentCollector, cli.json, save, &cli.db,
        ).await,
        Command::DnsCache { save } => run_simple_collector(
            "DNS cache entries", offgrd_collectors::DnsCacheCollector, cli.json, save, &cli.db,
        ).await,
        Command::Idle { save } => run_simple_collector(
            "idle state", offgrd_collectors::IdleTimeCollector, cli.json, save, &cli.db,
        ).await,
        Command::Export {
            kind,
            format,
            output,
            limit,
        } => export::run(kind, format, &output, limit, &cli.db),
    }
}

/// Generic runner for the newer, simpler snapshot collectors that
/// don't need a bespoke table layout: runs the collector through a
/// fresh bus, optionally persists, and prints either JSON (one Event
/// per line) or a generic `Debug`-based summary line per event. The
/// earlier collectors (`ps`, `net`, `autoruns`, `services`, `certs`)
/// keep their own hand-formatted table output (defined above) since
/// those were written before this helper existed and have real
/// column layouts worth preserving; new collectors default to this
/// instead of six more copy-pasted table-printing functions.
async fn run_simple_collector<C: Collector>(
    label: &str,
    collector: C,
    json: bool,
    save: bool,
    db_path: &str,
) -> Result<()> {
    let bus = EventBus::new();
    let mut subscription = bus.subscribe();
    collector.run(&bus).await?;

    let mut events: Vec<Event> = Vec::new();
    loop {
        match subscription.try_recv() {
            Ok(event) => events.push(event),
            Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
            Err(TryRecvError::Lagged(_)) => continue,
        }
    }

    if save {
        let store = EventStore::open(db_path)?;
        for event in &events {
            store.insert(event)?;
        }
        eprintln!("saved {} {label} to {db_path}", events.len());
    }

    if json {
        for event in &events {
            println!("{}", serde_json::to_string(event)?);
        }
        return Ok(());
    }

    if events.is_empty() {
        eprintln!("offgrd: no {label} observed.");
        return Ok(());
    }

    for event in &events {
        println!("{}", format_payload_summary(&event.payload));
    }

    Ok(())
}

/// A generic one-line human-readable rendering of any payload —
/// shared by `run_simple_collector` and, if useful later, other
/// generic display paths. Deliberately not as polished as the
/// hand-tuned table layouts for `ps`/`net`/`autoruns`/`services`/
/// `certs`, which have dedicated column formatting instead.
fn format_payload_summary(payload: &EventPayload) -> String {
    match payload {
        EventPayload::ProcessStarted { process } => {
            format!("[process] pid={} {}", process.pid, process.image_path.as_deref().unwrap_or("-"))
        }
        EventPayload::ProcessEnded { pid, .. } => format!("[process] pid={pid} ended"),
        EventPayload::NetworkConnectionObserved {
            local_addr, local_port, remote_addr, remote_port, state, ..
        } => format!("[network] {local_addr}:{local_port} -> {remote_addr}:{remote_port} [{state}]"),
        EventPayload::AutorunEntryObserved { hive, key_path, value_name, value_data } => {
            format!("[autorun] {hive}\\{key_path}\\{value_name} = {value_data}")
        }
        EventPayload::ServiceObserved { service_name, state, .. } => {
            format!("[service] {service_name} ({state})")
        }
        EventPayload::CertificateObserved { store_name, subject, .. } => {
            format!("[cert] [{store_name}] {subject}")
        }
        EventPayload::LoadedModuleObserved { pid, module_name, module_path, .. } => {
            format!("[module] pid={pid} {module_name} ({module_path})")
        }
        EventPayload::SessionObserved { session_id, state, station_name, user_name } => {
            format!(
                "[session] #{session_id} {station_name} [{state}] user={}",
                user_name.as_deref().unwrap_or("-")
            )
        }
        EventPayload::HostsFileEntryObserved { ip_address, hostname, .. } => {
            format!("[hosts] {ip_address} -> {hostname}")
        }
        EventPayload::StartupFolderEntryObserved { scope, file_name, full_path } => {
            format!("[startup] [{scope}] {file_name} ({full_path})")
        }
        EventPayload::NamedPipeObserved { pipe_name } => format!("[pipe] {pipe_name}"),
        EventPayload::InstalledProgramObserved { display_name, display_version, publisher, .. } => {
            format!(
                "[program] {display_name} {} ({})",
                display_version.as_deref().unwrap_or(""),
                publisher.as_deref().unwrap_or("unknown publisher"),
            )
        }
        EventPayload::ClipboardTextObserved { text } => {
            let preview: String = text.chars().take(80).collect();
            format!("[clipboard] {preview}{}", if text.chars().count() > 80 { "…" } else { "" })
        }
        EventPayload::LocalAccountObserved { kind, name, disabled, .. } => {
            format!("[account] [{kind}] {name}{}", if disabled == &Some(true) { " (disabled)" } else { "" })
        }
        EventPayload::NetworkShareObserved { share_name, local_path, .. } => {
            format!("[share] {share_name} -> {}", local_path.as_deref().unwrap_or("-"))
        }
        EventPayload::ForegroundWindowObserved { window_title, pid, .. } => {
            format!("[foreground] \"{window_title}\" pid={}", pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()))
        }
        EventPayload::EnvironmentVariableObserved { name, value } => {
            format!("[env] {name}={value}")
        }
        EventPayload::DnsCacheEntryObserved { hostname, record_type, data } => {
            format!("[dns-cache] {hostname} {record_type} {data}")
        }
        EventPayload::IdleStateObserved { idle_seconds } => {
            format!("[idle] {idle_seconds}s")
        }
        EventPayload::Note { message } => format!("[note] {message}"),
    }
}

/// Lists certificates in the system stores via `CertificatesCollector`.
/// Same bus-based pattern as the other snapshot subcommands.
async fn run_certs(json: bool, save: bool, db_path: &str) -> Result<()> {
    let bus = EventBus::new();
    let mut subscription = bus.subscribe();
    let collector = offgrd_collectors::CertificatesCollector;
    collector.run(&bus).await?;

    let mut events: Vec<Event> = Vec::new();
    loop {
        match subscription.try_recv() {
            Ok(event) => events.push(event),
            Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
            Err(TryRecvError::Lagged(_)) => continue,
        }
    }

    if save {
        let store = EventStore::open(db_path)?;
        for event in &events {
            store.insert(event)?;
        }
        eprintln!("saved {} certificate(s) to {db_path}", events.len());
    }

    if json {
        for event in &events {
            println!("{}", serde_json::to_string(event)?);
        }
        return Ok(());
    }

    println!("{:<6}  {:<45}  {:<45}  EXPIRES", "STORE", "SUBJECT", "ISSUER");
    for event in &events {
        if let EventPayload::CertificateObserved {
            store_name,
            subject,
            issuer,
            not_after,
            ..
        } = &event.payload
        {
            println!(
                "{:<6}  {:<45}  {:<45}  {}",
                store_name,
                truncate(subject, 45),
                truncate(issuer, 45),
                not_after.format("%Y-%m-%d"),
            );
        }
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{truncated}…")
    }
}

/// Lists Windows services via `ServicesCollector`. Same bus-based
/// pattern as `run_ps`/`run_net`/`run_autoruns`.
async fn run_services(json: bool, save: bool, db_path: &str) -> Result<()> {
    let bus = EventBus::new();
    let mut subscription = bus.subscribe();
    let collector = offgrd_collectors::ServicesCollector;
    collector.run(&bus).await?;

    let mut events: Vec<Event> = Vec::new();
    loop {
        match subscription.try_recv() {
            Ok(event) => events.push(event),
            Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
            Err(TryRecvError::Lagged(_)) => continue,
        }
    }

    if save {
        let store = EventStore::open(db_path)?;
        for event in &events {
            store.insert(event)?;
        }
        eprintln!("saved {} service(s) to {db_path}", events.len());
    }

    if json {
        for event in &events {
            println!("{}", serde_json::to_string(event)?);
        }
        return Ok(());
    }

    println!("{:<40}  {:<12}  {:<16}  DISPLAY NAME", "SERVICE NAME", "STATE", "TYPE");
    for event in &events {
        if let EventPayload::ServiceObserved {
            service_name,
            display_name,
            state,
            service_type,
            ..
        } = &event.payload
        {
            println!("{service_name:<40}  {state:<12}  {service_type:<16}  {display_name}");
        }
    }

    Ok(())
}

/// Lists registry Run/RunOnce autorun entries via `AutorunsCollector`.
/// Same bus-based pattern as `run_ps`/`run_net`.
async fn run_autoruns(json: bool, save: bool, db_path: &str) -> Result<()> {
    let bus = EventBus::new();
    let mut subscription = bus.subscribe();
    let collector = offgrd_collectors::AutorunsCollector;
    collector.run(&bus).await?;

    let mut events: Vec<Event> = Vec::new();
    loop {
        match subscription.try_recv() {
            Ok(event) => events.push(event),
            Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
            Err(TryRecvError::Lagged(_)) => continue,
        }
    }

    if save {
        let store = EventStore::open(db_path)?;
        for event in &events {
            store.insert(event)?;
        }
        eprintln!("saved {} autorun entry(ies) to {db_path}", events.len());
    }

    if json {
        for event in &events {
            println!("{}", serde_json::to_string(event)?);
        }
        return Ok(());
    }

    println!("{:<6}  {:<55}  {:<20}  DATA", "HIVE", "KEY", "NAME");
    for event in &events {
        if let EventPayload::AutorunEntryObserved {
            hive,
            key_path,
            value_name,
            value_data,
        } = &event.payload
        {
            println!("{hive:<6}  {key_path:<55}  {value_name:<20}  {value_data}");
        }
    }

    Ok(())
}

/// Lists active IPv4 TCP connections via `NetworkSnapshotCollector`.
/// Same bus-based pattern as `run_ps`.
async fn run_net(json: bool, save: bool, db_path: &str) -> Result<()> {
    let bus = EventBus::new();
    let mut subscription = bus.subscribe();
    let collector = offgrd_collectors::NetworkSnapshotCollector;
    collector.run(&bus).await?;

    let mut events: Vec<Event> = Vec::new();
    loop {
        match subscription.try_recv() {
            Ok(event) => events.push(event),
            Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
            Err(TryRecvError::Lagged(_)) => continue,
        }
    }

    if save {
        let store = EventStore::open(db_path)?;
        for event in &events {
            store.insert(event)?;
        }
        eprintln!("saved {} connection(s) to {db_path}", events.len());
    }

    if json {
        for event in &events {
            println!("{}", serde_json::to_string(event)?);
        }
        return Ok(());
    }

    println!(
        "{:<21}  {:<21}  {:<12}  PID",
        "LOCAL", "REMOTE", "STATE"
    );
    for event in &events {
        if let EventPayload::NetworkConnectionObserved {
            pid,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
        } = &event.payload
        {
            println!(
                "{:<21}  {:<21}  {:<12}  {}",
                format!("{local_addr}:{local_port}"),
                format!("{remote_addr}:{remote_port}"),
                state,
                pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
            );
        }
    }

    Ok(())
}

/// Lints every rule file in `rules_dir`, reporting each parse failure
/// individually rather than stopping at the first one — useful when
/// you've got several new/edited rules and want the full picture in
/// one pass.
fn run_rules_check(rules_dir: &str) -> Result<()> {
    let (ruleset, errors) = offgrd_rules::RuleSet::load_dir_report(rules_dir)?;

    println!(
        "offgrd: {} rule(s) loaded successfully from '{rules_dir}'",
        ruleset.len()
    );

    if errors.is_empty() {
        println!("offgrd: no problems found.");
        return Ok(());
    }

    println!("offgrd: {} file(s) failed to load:", errors.len());
    for error in &errors {
        println!("  - {error}");
    }

    anyhow::bail!("{} rule file(s) had errors", errors.len());
}

fn run_alert_history(json: bool, limit: i64, db_path: &str) -> Result<()> {
    let store = EventStore::open(db_path)?;
    let alerts = store.recent_alerts(limit)?;

    if alerts.is_empty() {
        eprintln!("no alerts stored in {db_path} yet — try `offgrd alerts --save` first");
        return Ok(());
    }

    if json {
        for alert in &alerts {
            println!("{}", serde_json::to_string(alert)?);
        }
        return Ok(());
    }

    println!(
        "{:<24}  {:<8}  {:<28}  RULE",
        "TIMESTAMP (UTC)", "SEVERITY", "RULE ID"
    );
    for alert in &alerts {
        println!(
            "{:<24}  {:<8}  {:<28}  {}",
            alert.timestamp.format("%Y-%m-%d %H:%M:%S"),
            format!("{:?}", alert.severity),
            alert.rule_id,
            alert.rule_title,
        );
    }

    Ok(())
}

/// Loads rules from `rules_dir` and evaluates them either against a
/// fresh process snapshot (default — same collector `ps` uses) or
/// against previously stored history (`--from-history`).
async fn run_alerts(
    json: bool,
    rules_dir: &str,
    from_history: bool,
    limit: i64,
    save: bool,
    db_path: &str,
) -> Result<()> {
    let ruleset = offgrd_rules::RuleSet::load_dir(rules_dir)?;
    if ruleset.is_empty() {
        eprintln!("offgrd: no rules loaded from '{rules_dir}' (missing directory or no *.yaml files) — nothing to evaluate.");
        return Ok(());
    }
    eprintln!("offgrd: loaded {} rule(s) from '{rules_dir}'", ruleset.len());

    let events: Vec<Event> = if from_history {
        let store = EventStore::open(db_path)?;
        store.recent(limit)?
    } else {
        let bus = EventBus::new();
        let mut subscription = bus.subscribe();
        let collector = ProcessSnapshotCollector;
        collector.run(&bus).await?;

        let mut events = Vec::new();
        loop {
            match subscription.try_recv() {
                Ok(event) => events.push(event),
                Err(TryRecvError::Empty) | Err(TryRecvError::Closed) => break,
                Err(TryRecvError::Lagged(_)) => continue,
            }
        }
        events
    };

    let alerts = ruleset.evaluate_all(&events);

    if save && !alerts.is_empty() {
        let store = EventStore::open(db_path)?;
        for alert in &alerts {
            store.insert_alert(alert)?;
        }
        eprintln!("offgrd: saved {} alert(s) to {db_path}", alerts.len());
    }

    if alerts.is_empty() {
        eprintln!(
            "offgrd: evaluated {} event(s), no rules matched.",
            events.len()
        );
        return Ok(());
    }

    if json {
        for alert in &alerts {
            println!("{}", serde_json::to_string(alert)?);
        }
        return Ok(());
    }

    println!(
        "{:<24}  {:<8}  {:<28}  RULE",
        "TIMESTAMP (UTC)", "SEVERITY", "RULE ID"
    );
    for alert in &alerts {
        println!(
            "{:<24}  {:<8}  {:<28}  {}",
            alert.timestamp.format("%Y-%m-%d %H:%M:%S"),
            format!("{:?}", alert.severity),
            alert.rule_id,
            alert.rule_title,
        );
    }

    Ok(())
}

#[cfg(windows)]
async fn run_watch(json: bool, seconds: u64, save: bool, db_path: &str) -> Result<()> {
    use offgrd_collectors::EtwProcessCollector;

    let bus = EventBus::new();
    let mut subscription = bus.subscribe();
    let collector = EtwProcessCollector;

    eprintln!(
        "offgrd: watching Microsoft-Windows-Kernel-Process via ETW{}. Press Ctrl+C to stop.",
        if seconds > 0 {
            format!(" for {seconds}s")
        } else {
            String::new()
        }
    );

    let store = if save {
        Some(EventStore::open(db_path)?)
    } else {
        None
    };

    // Run the (indefinitely-blocking) collector concurrently with a
    // print/store loop that drains the bus as events arrive, and stop
    // both when either Ctrl+C fires, --seconds elapses, or the
    // collector itself errors out.
    let printer = async {
        loop {
            match subscription.recv().await {
                Ok(event) => {
                    if let Some(store) = &store {
                        if let Err(err) = store.insert(&event) {
                            eprintln!("offgrd: failed to store event: {err:#}");
                        }
                    }
                    if json {
                        if let Ok(line) = serde_json::to_string(&event) {
                            println!("{line}");
                        }
                    } else {
                        print_watch_line(&event);
                    }
                }
                Err(_) => break, // Bus closed: collector side ended.
            }
        }
    };

    let timeout = async {
        if seconds > 0 {
            tokio::time::sleep(std::time::Duration::from_secs(seconds)).await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    tokio::select! {
        result = collector.run(&bus) => { result?; }
        _ = printer => {}
        _ = timeout => { eprintln!("offgrd: --seconds elapsed, stopping."); }
        _ = tokio::signal::ctrl_c() => { eprintln!("offgrd: Ctrl+C received, stopping."); }
    }

    Ok(())
}

#[cfg(not(windows))]
async fn run_watch(_json: bool, _seconds: u64, _save: bool, _db_path: &str) -> Result<()> {
    anyhow::bail!(
        "`offgrd watch` uses ETW and is only implemented on Windows. Build and run this on Windows 10/11."
    )
}

#[cfg(windows)]
fn print_watch_line(event: &Event) {
    match &event.payload {
        EventPayload::ProcessStarted { process } => {
            println!(
                "[START] pid={:<8} ppid={:<8} {}",
                process.pid,
                process
                    .parent_pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                process.image_path.as_deref().unwrap_or("-"),
            );
        }
        EventPayload::ProcessEnded { pid, exit_code } => {
            println!(
                "[STOP]  pid={:<8} exit_code={}",
                pid,
                exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
        }
        _ => {}
    }
}

/// Runs the process-snapshot collector through a real `EventBus` and
/// renders whatever it published. The bus/collector plumbing here is
/// intentionally visible (not hidden behind a one-liner) since this
/// is the reference example every future subcommand will copy.
async fn run_ps(json: bool, tree: bool, save: bool, db_path: &str) -> Result<()> {
    let bus = EventBus::new();
    let mut subscription = bus.subscribe();

    let collector = ProcessSnapshotCollector;
    collector.run(&bus).await?;

    // The collector is one-shot and has already returned, so every
    // event it published is sitting in our subscription's buffer now.
    // Drain it with try_recv rather than recv().await: there is no
    // more data coming on this bus, so awaiting would hang forever
    // once the buffer is empty.
    let mut events: Vec<Event> = Vec::new();
    loop {
        match subscription.try_recv() {
            Ok(event) => events.push(event),
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Lagged(skipped)) => {
                eprintln!("warning: process-snapshot collector output was truncated, {skipped} event(s) dropped (bus capacity exceeded)");
            }
            Err(TryRecvError::Closed) => break,
        }
    }

    if save {
        let store = EventStore::open(db_path)?;
        for event in &events {
            store.insert(event)?;
        }
        eprintln!("saved {} event(s) to {db_path}", events.len());
    }

    if json {
        for event in &events {
            println!("{}", serde_json::to_string(event)?);
        }
        return Ok(());
    }

    if tree {
        print_tree(&events);
        return Ok(());
    }

    println!("{:>8}  {:>8}  {:<40}  COMMAND LINE", "PID", "PPID", "IMAGE");
    for event in &events {
        let EventPayload::ProcessStarted { process } = &event.payload else {
            continue;
        };
        println!(
            "{:>8}  {:>8}  {:<40}  {}",
            process.pid,
            process
                .parent_pid
                .map(|p| p.to_string())
                .unwrap_or_else(|| "-".to_string()),
            process.image_path.as_deref().unwrap_or("-"),
            process.command_line.as_deref().unwrap_or(""),
        );
    }

    Ok(())
}

/// Reads back previously stored events from the event store — proves
/// the storage round-trip end to end via the CLI, independent of the
/// unit tests in `offgrd-core`.
fn run_history(json: bool, limit: i64, db_path: &str) -> Result<()> {
    let store = EventStore::open(db_path)?;
    let events = store.recent(limit)?;

    if events.is_empty() {
        eprintln!("no events stored in {db_path} yet — try `offgrd ps --save` first");
        return Ok(());
    }

    if json {
        for event in &events {
            println!("{}", serde_json::to_string(event)?);
        }
        return Ok(());
    }

    println!(
        "{:<24}  {:>8}  {:>8}  IMAGE",
        "TIMESTAMP (UTC)", "PID", "PPID"
    );
    for event in &events {
        if let EventPayload::ProcessStarted { process } = &event.payload {
            println!(
                "{:<24}  {:>8}  {:>8}  {}",
                event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                process.pid,
                process
                    .parent_pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                process.image_path.as_deref().unwrap_or("-"),
            );
        }
    }

    Ok(())
}

/// Renders the flat process list as an indented parent -> child tree.
///
/// Roots are processes whose `parent_pid` doesn't correspond to any
/// pid we actually saw in this snapshot (either it's pid 0/4/System,
/// or the parent already exited — both are normal). This is a display
/// concern only: no cycle-detection subtlety needed since we do a
/// straightforward recursive walk over a pid->children map and guard
/// against re-visiting a pid via `visited`.
fn print_tree(events: &[Event]) {
    use std::collections::{HashMap, HashSet};

    let mut by_pid: HashMap<u32, &offgrd_common::ProcessRef> = HashMap::new();
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();

    for event in events {
        if let EventPayload::ProcessStarted { process } = &event.payload {
            by_pid.insert(process.pid, process);
        }
    }
    for process in by_pid.values() {
        if let Some(ppid) = process.parent_pid {
            if by_pid.contains_key(&ppid) && ppid != process.pid {
                children.entry(ppid).or_default().push(process.pid);
            }
        }
    }

    let all_pids: HashSet<u32> = by_pid.keys().copied().collect();
    let child_pids: HashSet<u32> = children.values().flatten().copied().collect();
    let mut roots: Vec<u32> = all_pids.difference(&child_pids).copied().collect();
    roots.sort_unstable();

    let mut visited: HashSet<u32> = HashSet::new();
    for root in roots {
        print_node(root, 0, &by_pid, &children, &mut visited);
    }
}

fn print_node(
    pid: u32,
    depth: usize,
    by_pid: &std::collections::HashMap<u32, &offgrd_common::ProcessRef>,
    children: &std::collections::HashMap<u32, Vec<u32>>,
    visited: &mut std::collections::HashSet<u32>,
) {
    if !visited.insert(pid) {
        return; // Defensive: avoid infinite loop if data is ever malformed.
    }

    if let Some(process) = by_pid.get(&pid) {
        let indent = "  ".repeat(depth);
        let name = process.image_path.as_deref().unwrap_or("-");
        println!("{indent}├─ [{pid}] {name}");
    }

    if let Some(kids) = children.get(&pid) {
        let mut kids = kids.clone();
        kids.sort_unstable();
        for kid in kids {
            print_node(kid, depth + 1, by_pid, children, visited);
        }
    }
}
