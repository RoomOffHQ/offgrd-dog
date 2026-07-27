// OffGrd Dog GUI frontend.
//
// Deliberately vanilla JS, no build step: `withGlobalTauri: true` in
// tauri.conf.json exposes `window.__TAURI__.invoke` directly, so this
// file can be served as-is as Tauri's distDir with zero bundler. If
// this ever needs to grow into something more complex (state
// management, routing), that's the point to introduce a real
// frontend framework — not before.

const invoke = window.__TAURI__ ? window.__TAURI__.invoke : null;
const tauriEvent = window.__TAURI__ ? window.__TAURI__.event : null;

// Rolling buffers of events pushed by the backend's always-on live
// monitor (see src-tauri/src/live.rs), separate from the "click
// Refresh/Scan now" snapshots — merged into the same tables so the
// user doesn't need to think about which source a row came from.
const liveProcessEvents = [];
const liveAlerts = [];
const MAX_LIVE_ROWS = 500; // Cap growth for a long-running session.

// Fallback so this is at least inspectable in a normal browser tab
// during frontend-only iteration (no Tauri backend attached) — every
// call resolves with empty/placeholder data instead of throwing.
async function callBackend(command, args = {}) {
  if (!invoke) {
    console.warn(`[offgrd-gui] Tauri bridge not present; "${command}" returning stub data.`);
    return stubFor(command);
  }
  return invoke(command, args);
}

function stubFor(command) {
  switch (command) {
    case "list_processes":
      return [];
    case "run_alerts_scan":
    case "get_alert_history":
      return [];
    case "list_rules":
      return [];
    case "list_network":
    case "list_autoruns":
    case "list_services":
    case "list_certificates":
    case "list_modules":
    case "list_sessions":
    case "list_hosts_entries":
    case "list_startup_items":
    case "list_named_pipes":
    case "list_installed_programs":
      return [];
    case "get_clipboard_snapshot":
      return null;
    case "get_monitoring_mode":
      return "normal";
    case "set_monitoring_mode":
      return null;
    case "get_dashboard_summary":
      return {
        process_count: 0,
        stored_event_count: 0,
        stored_alert_count: 0,
        loaded_rule_count: 0,
        rule_load_errors: ["Tauri bridge not available in this context."],
      };
    default:
      return null;
  }
}

// ---------- Navigation ----------

function setupNav() {
  const navItems = document.querySelectorAll(".nav-item");
  navItems.forEach((item) => {
    item.addEventListener("click", () => {
      navItems.forEach((i) => i.classList.remove("active"));
      item.classList.add("active");

      const target = item.dataset.view;
      document.querySelectorAll(".view").forEach((view) => view.classList.remove("active"));
      document.getElementById(`view-${target}`).classList.add("active");
    });
  });
}

// ---------- Dashboard ----------

async function refreshDashboard() {
  setConnectionStatus("loading");
  try {
    const summary = await callBackend("get_dashboard_summary");
    document.getElementById("stat-processes").textContent = summary.process_count;
    document.getElementById("stat-events").textContent = summary.stored_event_count;
    document.getElementById("stat-alerts").textContent = summary.stored_alert_count;
    document.getElementById("stat-rules").textContent = summary.loaded_rule_count;

    const pathsEl = document.getElementById("data-paths");
    if (pathsEl) {
      pathsEl.innerHTML = `Database: <code>${escapeHtml(summary.db_path)}</code><br/>Rules: <code>${escapeHtml(summary.rules_dir)}</code>`;
    }

    const errorsPanel = document.getElementById("rule-errors-panel");
    const errorsList = document.getElementById("rule-errors-list");
    if (summary.rule_load_errors && summary.rule_load_errors.length > 0) {
      errorsPanel.style.display = "block";
      errorsList.innerHTML = "";
      summary.rule_load_errors.forEach((err) => {
        const li = document.createElement("li");
        li.textContent = err;
        errorsList.appendChild(li);
      });
    } else {
      errorsPanel.style.display = "none";
    }
    setConnectionStatus("ok");
  } catch (err) {
    console.error(err);
    setConnectionStatus("error");
  }
}

function setConnectionStatus(status) {
  const dot = document.getElementById("connection-dot");
  const label = document.getElementById("connection-label");
  if (status === "ok") {
    dot.style.background = "var(--green)";
    label.textContent = "Ready";
  } else if (status === "loading") {
    dot.style.background = "var(--yellow)";
    label.textContent = "Working…";
  } else {
    dot.style.background = "var(--red)";
    label.textContent = "Error — see console";
  }
}

// ---------- Processes ----------

let currentProcesses = [];
let currentAlerts = [];
let processSortKey = "pid";
let processSortAsc = true;

async function refreshProcesses() {
  setConnectionStatus("loading");
  try {
    currentProcesses = await callBackend("list_processes");
    if (processViewMode === "tree") {
      renderProcessTree();
    } else {
      renderProcessTable();
    }
    setConnectionStatus("ok");
  } catch (err) {
    console.error(err);
    setConnectionStatus("error");
  }
}

function renderProcessTable() {
  const filterText = document.getElementById("process-search").value.trim().toLowerCase();
  const body = document.getElementById("process-table-body");
  body.innerHTML = "";

  let rows = currentProcesses.filter((p) => {
    if (!filterText) return true;
    return (
      String(p.pid).includes(filterText) ||
      (p.image_path && p.image_path.toLowerCase().includes(filterText)) ||
      (p.command_line && p.command_line.toLowerCase().includes(filterText))
    );
  });

  rows.sort((a, b) => {
    const av = a[processSortKey] ?? "";
    const bv = b[processSortKey] ?? "";
    if (av < bv) return processSortAsc ? -1 : 1;
    if (av > bv) return processSortAsc ? 1 : -1;
    return 0;
  });

  if (rows.length === 0) {
    body.innerHTML = '<tr><td colspan="4" class="empty-row">No matching processes.</td></tr>';
    return;
  }

  for (const p of rows) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${p.pid}</td>
      <td class="mono">${p.ppid ?? "-"}</td>
      <td class="mono">${escapeHtml(p.image_path || "-")}</td>
      <td class="mono">${escapeHtml(p.command_line || "")}</td>
    `;
    body.appendChild(tr);
  }
}

function setupProcessTableSorting() {
  document.querySelectorAll("#view-processes thead th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      if (processSortKey === key) {
        processSortAsc = !processSortAsc;
      } else {
        processSortKey = key;
        processSortAsc = true;
      }
      renderProcessTable();
    });
  });
}

let processViewMode = "table"; // "table" | "tree"

function setupProcessViewToggle() {
  const btn = document.getElementById("toggle-process-view");
  btn.addEventListener("click", () => {
    processViewMode = processViewMode === "table" ? "tree" : "table";
    btn.textContent = processViewMode === "table" ? "Tree view" : "Table view";
    document.getElementById("process-table-wrap").style.display =
      processViewMode === "table" ? "block" : "none";
    document.getElementById("process-tree-wrap").style.display =
      processViewMode === "tree" ? "block" : "none";
    if (processViewMode === "tree") renderProcessTree();
  });
}

// Mirrors the CLI's `offgrd ps --tree` logic (see
// crates/offgrd-cli/src/main.rs::print_tree) in JS: roots are
// processes whose ppid isn't in this snapshot at all (already exited,
// or pid 0/4/System), walked recursively with a visited-set guard
// against malformed/cyclic data.
function renderProcessTree() {
  const byPid = new Map();
  const children = new Map();

  for (const p of currentProcesses) byPid.set(p.pid, p);
  for (const p of currentProcesses) {
    if (p.ppid != null && byPid.has(p.ppid) && p.ppid !== p.pid) {
      if (!children.has(p.ppid)) children.set(p.ppid, []);
      children.get(p.ppid).push(p.pid);
    }
  }

  const childPids = new Set([...children.values()].flat());
  const roots = [...byPid.keys()].filter((pid) => !childPids.has(pid)).sort((a, b) => a - b);

  const lines = [];
  const visited = new Set();

  function visit(pid, depth) {
    if (visited.has(pid)) return;
    visited.add(pid);
    const p = byPid.get(pid);
    if (p) {
      const indent = "  ".repeat(depth);
      lines.push(`${indent}├─ [${pid}] ${p.image_path || "-"}`);
    }
    const kids = (children.get(pid) || []).slice().sort((a, b) => a - b);
    for (const kid of kids) visit(kid, depth + 1);
  }

  for (const root of roots) visit(root, 0);

  document.getElementById("process-tree").textContent =
    lines.length > 0 ? lines.join("\n") : "No processes loaded — click Refresh first.";
}

// ---------- Alerts ----------

function severityBadgeClass(severity) {
  switch ((severity || "").toLowerCase()) {
    case "info": return "badge-info";
    case "low": return "badge-low";
    case "medium": return "badge-medium";
    case "high": return "badge-high";
    case "critical": return "badge-critical";
    default: return "badge-info";
  }
}

function renderAlertTable(alerts) {
  currentAlerts = alerts || [];
  const body = document.getElementById("alert-table-body");
  body.innerHTML = "";

  if (!alerts || alerts.length === 0) {
    body.innerHTML = '<tr><td colspan="4" class="empty-row">No alerts.</td></tr>';
    return;
  }

  // Newest first.
  const sorted = [...alerts].sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));
  currentAlerts = sorted;

  for (const alert of sorted) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><span class="badge ${severityBadgeClass(alert.severity)}">${escapeHtml(alert.severity)}</span></td>
      <td>${escapeHtml(alert.rule_title)}<br/><span class="mono" style="color:var(--text-muted)">${escapeHtml(alert.rule_id)}</span></td>
      <td class="mono">${new Date(alert.timestamp).toLocaleString()}</td>
      <td class="mono" style="color:var(--text-muted)">${escapeHtml(alert.triggering_event_id.slice(0, 8))}…</td>
    `;
    body.appendChild(tr);
  }
}

async function scanNow() {
  setConnectionStatus("loading");
  try {
    const alerts = await callBackend("run_alerts_scan", { rulesDir: null });
    renderAlertTable(alerts);
    setConnectionStatus("ok");
  } catch (err) {
    console.error(err);
    setConnectionStatus("error");
  }
}

async function loadAlertHistory() {
  setConnectionStatus("loading");
  try {
    const alerts = await callBackend("get_alert_history", { limit: 200 });
    renderAlertTable(alerts);
    setConnectionStatus("ok");
  } catch (err) {
    console.error(err);
    setConnectionStatus("error");
  }
}

// ---------- Simple snapshot views (Network / Autoruns / Services / Certificates) ----------
//
// These four views share the same shape: fetch a flat list from a
// Tauri command, optionally filter by a search box, render as a
// table. Factored into one generic helper rather than four near-
// identical copies of refreshProcesses'-style code.

const simpleViews = {
  network: {
    command: "list_network",
    searchId: "network-search",
    bodyId: "network-table-body",
    columns: 4,
    matches: (row, q) =>
      row.local_addr.toLowerCase().includes(q) ||
      row.remote_addr.toLowerCase().includes(q) ||
      String(row.pid ?? "").includes(q),
    renderRow: (row) => `
      <td class="mono">${escapeHtml(row.local_addr)}:${row.local_port}</td>
      <td class="mono">${escapeHtml(row.remote_addr)}:${row.remote_port}</td>
      <td class="mono">${escapeHtml(row.state)}</td>
      <td class="mono">${row.pid ?? "-"}</td>
    `,
  },
  autoruns: {
    command: "list_autoruns",
    searchId: "autoruns-search",
    bodyId: "autoruns-table-body",
    columns: 4,
    matches: (row, q) =>
      row.value_name.toLowerCase().includes(q) || row.value_data.toLowerCase().includes(q),
    renderRow: (row) => `
      <td class="mono">${escapeHtml(row.hive)}</td>
      <td class="mono">${escapeHtml(row.key_path)}</td>
      <td class="mono">${escapeHtml(row.value_name)}</td>
      <td class="mono">${escapeHtml(row.value_data)}</td>
    `,
  },
  services: {
    command: "list_services",
    searchId: "services-search",
    bodyId: "services-table-body",
    columns: 4,
    matches: (row, q) =>
      row.service_name.toLowerCase().includes(q) || row.display_name.toLowerCase().includes(q),
    renderRow: (row) => `
      <td class="mono">${escapeHtml(row.service_name)}</td>
      <td class="mono">${escapeHtml(row.state)}</td>
      <td class="mono">${escapeHtml(row.service_type)}</td>
      <td>${escapeHtml(row.display_name)}</td>
    `,
  },
  certificates: {
    command: "list_certificates",
    searchId: "certificates-search",
    bodyId: "certificates-table-body",
    columns: 4,
    matches: (row, q) =>
      row.subject.toLowerCase().includes(q) || row.issuer.toLowerCase().includes(q),
    renderRow: (row) => `
      <td class="mono">${escapeHtml(row.store_name)}</td>
      <td>${escapeHtml(row.subject)}</td>
      <td>${escapeHtml(row.issuer)}</td>
      <td class="mono">${new Date(row.not_after).toLocaleDateString()}</td>
    `,
  },
  modules: {
    command: "list_modules",
    searchId: "modules-search",
    bodyId: "modules-table-body",
    columns: 4,
    matches: (row, q) =>
      row.module_name.toLowerCase().includes(q) || row.module_path.toLowerCase().includes(q) || String(row.pid).includes(q),
    renderRow: (row) => `
      <td class="mono">${row.pid}</td>
      <td class="mono">${escapeHtml(row.module_name)}</td>
      <td class="mono">${escapeHtml(row.module_path)}</td>
      <td class="mono">${row.base_size}</td>
    `,
  },
  sessions: {
    command: "list_sessions",
    searchId: "sessions-search",
    bodyId: "sessions-table-body",
    columns: 4,
    matches: (row, q) =>
      row.station_name.toLowerCase().includes(q) || (row.user_name || "").toLowerCase().includes(q),
    renderRow: (row) => `
      <td class="mono">${row.session_id}</td>
      <td class="mono">${escapeHtml(row.station_name)}</td>
      <td class="mono">${escapeHtml(row.state)}</td>
      <td>${escapeHtml(row.user_name || "-")}</td>
    `,
  },
  hosts: {
    command: "list_hosts_entries",
    searchId: "hosts-search",
    bodyId: "hosts-table-body",
    columns: 4,
    matches: (row, q) =>
      row.ip_address.toLowerCase().includes(q) || row.hostname.toLowerCase().includes(q),
    renderRow: (row) => `
      <td class="mono">${escapeHtml(row.ip_address)}</td>
      <td class="mono">${escapeHtml(row.hostname)}</td>
      <td class="mono" colspan="2">${escapeHtml(row.raw_line)}</td>
    `,
  },
  "startup-items": {
    command: "list_startup_items",
    searchId: "startup-items-search",
    bodyId: "startup-items-table-body",
    columns: 4,
    matches: (row, q) => row.file_name.toLowerCase().includes(q),
    renderRow: (row) => `
      <td class="mono">${escapeHtml(row.scope)}</td>
      <td class="mono">${escapeHtml(row.file_name)}</td>
      <td class="mono" colspan="2">${escapeHtml(row.full_path)}</td>
    `,
  },
  pipes: {
    command: "list_named_pipes",
    searchId: "pipes-search",
    bodyId: "pipes-table-body",
    columns: 4,
    matches: (row, q) => row.pipe_name.toLowerCase().includes(q),
    renderRow: (row) => `<td class="mono" colspan="4">${escapeHtml(row.pipe_name)}</td>`,
  },
  programs: {
    command: "list_installed_programs",
    searchId: "programs-search",
    bodyId: "programs-table-body",
    columns: 4,
    matches: (row, q) =>
      row.display_name.toLowerCase().includes(q) || (row.publisher || "").toLowerCase().includes(q),
    renderRow: (row) => `
      <td>${escapeHtml(row.display_name)}</td>
      <td class="mono">${escapeHtml(row.display_version || "-")}</td>
      <td>${escapeHtml(row.publisher || "-")}</td>
      <td class="mono">${escapeHtml(row.install_location || "-")}</td>
    `,
  },
};

const simpleViewData = {}; // viewKey -> last-fetched rows, for client-side filtering

async function refreshSimpleView(viewKey) {
  const config = simpleViews[viewKey];
  setConnectionStatus("loading");
  try {
    const rows = await callBackend(config.command);
    simpleViewData[viewKey] = rows || [];
    renderSimpleView(viewKey);
    setConnectionStatus("ok");
  } catch (err) {
    console.error(err);
    setConnectionStatus("error");
  }
}

function renderSimpleView(viewKey) {
  const config = simpleViews[viewKey];
  const rows = simpleViewData[viewKey] || [];
  const searchEl = document.getElementById(config.searchId);
  const query = (searchEl?.value || "").trim().toLowerCase();

  const filtered = query ? rows.filter((row) => config.matches(row, query)) : rows;

  const body = document.getElementById(config.bodyId);
  if (filtered.length === 0) {
    body.innerHTML = `<tr><td colspan="${config.columns}" class="empty-row">No matching entries.</td></tr>`;
    return;
  }

  body.innerHTML = filtered.map((row) => `<tr>${config.renderRow(row)}</tr>`).join("");
}

function setupSimpleViews() {
  for (const viewKey of Object.keys(simpleViews)) {
    const config = simpleViews[viewKey];
    document
      .getElementById(`refresh-${viewKey}`)
      .addEventListener("click", () => refreshSimpleView(viewKey));
    document
      .getElementById(config.searchId)
      .addEventListener("input", () => renderSimpleView(viewKey));
  }
}

// ---------- Clipboard (privacy-sensitive: explicit reveal only) ----------

async function revealClipboard() {
  const box = document.getElementById("clipboard-content");
  setConnectionStatus("loading");
  try {
    const text = await callBackend("get_clipboard_snapshot");
    box.style.display = "block";
    box.textContent = text ? text : "(clipboard is empty or contains no text)";
    setConnectionStatus("ok");
  } catch (err) {
    console.error(err);
    box.style.display = "block";
    box.textContent = "Could not read clipboard.";
    setConnectionStatus("error");
  }
}

// ---------- Rules ----------

async function refreshRules() {
  setConnectionStatus("loading");
  try {
    const rules = await callBackend("list_rules", { rulesDir: null });
    renderRulesList(rules);
    setConnectionStatus("ok");
  } catch (err) {
    console.error(err);
    setConnectionStatus("error");
  }
}

function renderRulesList(rules) {
  const container = document.getElementById("rules-list");
  container.innerHTML = "";

  if (!rules || rules.length === 0) {
    container.innerHTML = '<div class="panel"><p class="muted">No rules loaded. Check that the <code>rules/</code> directory exists and contains *.yaml files.</p></div>';
    return;
  }

  for (const rule of rules) {
    const card = document.createElement("div");
    card.className = "rule-card";
    card.innerHTML = `
      <div class="rule-card-header">
        <div class="rule-card-title">${escapeHtml(rule.title)}</div>
        <span class="badge ${severityBadgeClass(rule.severity)}">${escapeHtml(rule.severity)}</span>
      </div>
      <div class="rule-card-id">${escapeHtml(rule.id)}</div>
      ${rule.description ? `<div class="rule-card-description">${escapeHtml(rule.description)}</div>` : ""}
      <div class="rule-card-condition">${escapeHtml(rule.condition_summary)}</div>
      ${rule.mitre_attack_id ? `<div class="rule-card-mitre">MITRE ATT&amp;CK: ${escapeHtml(rule.mitre_attack_id)}</div>` : ""}
    `;
    container.appendChild(card);
  }
}

// ---------- Export (JSON/CSV) ----------
//
// Uses Tauri's `dialog.save` (native Save As… dialog) + `fs.writeFile`
// rather than a browser-style <a download> trick — the latter is
// unreliable inside a webview and doesn't let the user pick where the
// file goes, which matters for a security tool's forensic exports
// (see the architecture doc's Exports module: JSON/CSV/etc. are meant
// to be real artifacts the user files away, not a throwaway download).

function toCsv(rows, columns) {
  const escapeCell = (value) => {
    const s = value === null || value === undefined ? "" : String(value);
    if (s.includes(",") || s.includes('"') || s.includes("\n")) {
      return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
  };
  const header = columns.map((c) => escapeCell(c.label)).join(",");
  const body = rows
    .map((row) => columns.map((c) => escapeCell(row[c.key])).join(","))
    .join("\n");
  return `${header}\n${body}`;
}

async function saveTextFile(content, suggestedName, extensionLabel, extensions) {
  const dialog = window.__TAURI__ ? window.__TAURI__.dialog : null;
  const fs = window.__TAURI__ ? window.__TAURI__.fs : null;

  if (!dialog || !fs) {
    console.warn("[offgrd-gui] Tauri dialog/fs bridge not present; export unavailable in this context.");
    alert("Export requires running inside the OffGrd Dog desktop app.");
    return;
  }

  const path = await dialog.save({
    defaultPath: suggestedName,
    filters: [{ name: extensionLabel, extensions }],
  });
  if (!path) return; // User cancelled the dialog.

  await fs.writeFile({ path, contents: content });
}

async function exportProcessesJson() {
  await saveTextFile(
    JSON.stringify(currentProcesses, null, 2),
    "offgrd-processes.json",
    "JSON",
    ["json"],
  );
}

async function exportProcessesCsv() {
  const csv = toCsv(currentProcesses, [
    { key: "pid", label: "PID" },
    { key: "ppid", label: "PPID" },
    { key: "image_path", label: "Image Path" },
    { key: "command_line", label: "Command Line" },
  ]);
  await saveTextFile(csv, "offgrd-processes.csv", "CSV", ["csv"]);
}

async function exportAlertsJson() {
  await saveTextFile(
    JSON.stringify(currentAlerts, null, 2),
    "offgrd-alerts.json",
    "JSON",
    ["json"],
  );
}

async function exportAlertsCsv() {
  const csv = toCsv(currentAlerts, [
    { key: "timestamp", label: "Timestamp" },
    { key: "severity", label: "Severity" },
    { key: "rule_id", label: "Rule ID" },
    { key: "rule_title", label: "Rule Title" },
    { key: "triggering_event_id", label: "Triggering Event ID" },
  ]);
  await saveTextFile(csv, "offgrd-alerts.csv", "CSV", ["csv"]);
}

// ---------- Utilities ----------

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value;
  return div.innerHTML;
}

// ---------- Live events (from the always-on background monitor) ----------

function setupLiveEvents() {
  if (!tauriEvent) {
    console.warn("[offgrd-gui] Tauri event bridge not present; live updates disabled.");
    return;
  }

  tauriEvent.listen("offgrd://process-event", (evt) => {
    const process = evt.payload;
    liveProcessEvents.unshift(process);
    if (liveProcessEvents.length > MAX_LIVE_ROWS) liveProcessEvents.pop();

    // Merge into whatever's currently shown so a live view doesn't
    // require the user to hit Refresh to see new activity.
    if (!currentProcesses.some((p) => p.pid === process.pid)) {
      currentProcesses.unshift(process);
      renderProcessTable();
    }
    bumpLiveCounter("process");
  });

  tauriEvent.listen("offgrd://alert-event", (evt) => {
    const alert = evt.payload;
    liveAlerts.unshift(alert);
    if (liveAlerts.length > MAX_LIVE_ROWS) liveAlerts.pop();

    renderAlertTable(liveAlerts);
    bumpLiveCounter("alert");
    flashConnectionDot();
    recordSeverityForThreatGauge(alert.severity);
    showToast({
      severity: alert.severity,
      title: `Alert: ${alert.rule_title}`,
      body: alert.rule_id,
    });
  });

  tauriEvent.listen("offgrd://activity", (evt) => {
    const notice = evt.payload;
    showToast({
      severity: "info",
      title: "Paranoid scan activity",
      body: notice.message,
    });
  });
}

let liveEventCount = 0;
function bumpLiveCounter() {
  liveEventCount += 1;
  const label = document.getElementById("connection-label");
  if (label) label.textContent = `Live — ${liveEventCount} event(s) observed`;
}

function flashConnectionDot() {
  const dot = document.getElementById("connection-dot");
  if (!dot) return;
  dot.style.background = "var(--accent)";
  setTimeout(() => {
    dot.style.background = "var(--green)";
  }, 400);
}

// ---------- Monitoring mode switcher ----------

async function setMonitoringMode(mode) {
  document.querySelectorAll(".mode-option").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.mode === mode);
  });
  try {
    await callBackend("set_monitoring_mode", { mode });
    showToast({
      severity: "info",
      title: `Monitoring posture: ${mode[0].toUpperCase()}${mode.slice(1)}`,
      body: modeDescription(mode),
    });
  } catch (err) {
    console.error(err);
  }
}

function modeDescription(mode) {
  switch (mode) {
    case "normal":
      return "Background monitoring is off. Everything runs on demand only.";
    case "moderate":
      return "Live process monitoring every 10s.";
    case "paranoid":
      return "Fast process monitoring (3s) plus periodic full-spectrum scans across network, autoruns, services, and certificates.";
    default:
      return "";
  }
}

async function setupModeSwitcher() {
  document.querySelectorAll(".mode-option").forEach((btn) => {
    btn.addEventListener("click", () => setMonitoringMode(btn.dataset.mode));
  });

  try {
    const current = await callBackend("get_monitoring_mode");
    const mode = typeof current === "string" ? current : "normal";
    document.querySelectorAll(".mode-option").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.mode === mode);
    });
  } catch (err) {
    console.warn("[offgrd-gui] could not fetch current monitoring mode", err);
    document.querySelector('.mode-option[data-mode="normal"]')?.classList.add("active");
  }
}

// ---------- Toast notifications ----------

function showToast({ severity, title, body }) {
  const container = document.getElementById("toast-container");
  const toast = document.createElement("div");
  toast.className = `toast toast-${(severity || "info").toLowerCase()}`;
  toast.innerHTML = `
    <div class="toast-title">${escapeHtml(title)}</div>
    <div class="toast-body">${escapeHtml(body || "")}</div>
  `;
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add("toast-leaving");
    setTimeout(() => toast.remove(), 220);
  }, 5000);
}

// ---------- Threat gauge ----------

// Rolling window of recent alert severities (in-memory only, resets
// on app restart) used purely to drive the dashboard's Threat Level
// gauge — a quick "how spicy has it been lately" visual, not a
// scored/validated risk metric.
const recentSeverities = [];
const THREAT_WINDOW = 50;

function recordSeverityForThreatGauge(severity) {
  recentSeverities.push((severity || "info").toLowerCase());
  if (recentSeverities.length > THREAT_WINDOW) recentSeverities.shift();
  updateThreatGauge();
}

function updateThreatGauge() {
  const fill = document.getElementById("threat-gauge-fill");
  const label = document.getElementById("threat-gauge-label");
  if (!fill || !label) return;

  if (recentSeverities.length === 0) {
    fill.style.width = "4%";
    label.textContent = "No alerts observed yet — looking calm.";
    return;
  }

  const weights = { info: 5, low: 20, medium: 45, high: 75, critical: 100 };
  const avg =
    recentSeverities.reduce((sum, s) => sum + (weights[s] ?? 20), 0) / recentSeverities.length;

  fill.style.width = `${Math.min(100, Math.round(avg))}%`;

  if (avg < 20) label.textContent = "Low — mostly informational activity.";
  else if (avg < 45) label.textContent = "Moderate — some low/medium severity alerts recently.";
  else if (avg < 75) label.textContent = "Elevated — medium/high severity alerts recently. Worth a look.";
  else label.textContent = "High — high/critical severity alerts recently. Investigate the Alerts page.";
}

// ---------- Keyboard shortcuts ----------

function setupKeyboardShortcuts() {
  const viewOrder = ["dashboard", "processes", "alerts", "network", "autoruns", "services", "certificates", "rules"];
  document.addEventListener("keydown", (e) => {
    // Don't hijack shortcuts while the user is typing in a search box.
    if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") {
      if (e.key === "Escape") e.target.blur();
      return;
    }

    const num = parseInt(e.key, 10);
    if (!Number.isNaN(num) && num >= 1 && num <= viewOrder.length) {
      document.querySelector(`.nav-item[data-view="${viewOrder[num - 1]}"]`)?.click();
    }
  });
}

// ---------- Wire it all up ----------

document.addEventListener("DOMContentLoaded", () => {
  setupNav();
  setupProcessTableSorting();
  setupProcessViewToggle();
  setupSimpleViews();
  setupModeSwitcher();
  setupKeyboardShortcuts();

  document.getElementById("refresh-dashboard").addEventListener("click", refreshDashboard);
  document.getElementById("refresh-processes").addEventListener("click", refreshProcesses);
  document.getElementById("process-search").addEventListener("input", renderProcessTable);
  document.getElementById("scan-now").addEventListener("click", scanNow);
  document.getElementById("load-alert-history").addEventListener("click", loadAlertHistory);
  document.getElementById("refresh-rules").addEventListener("click", refreshRules);
  document.getElementById("export-processes-json").addEventListener("click", exportProcessesJson);
  document.getElementById("export-processes-csv").addEventListener("click", exportProcessesCsv);
  document.getElementById("export-alerts-json").addEventListener("click", exportAlertsJson);
  document.getElementById("export-alerts-csv").addEventListener("click", exportAlertsCsv);
  document.getElementById("reveal-clipboard").addEventListener("click", revealClipboard);

  setupLiveEvents();

  // Initial load.
  refreshDashboard();
  refreshRules();
});
