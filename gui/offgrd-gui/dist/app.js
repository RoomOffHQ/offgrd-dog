// OffGrd Dog GUI frontend.
//
// Deliberately vanilla JS, no build step: `withGlobalTauri: true` in
// tauri.conf.json exposes `window.__TAURI__.invoke` directly, so this
// file can be served as-is as Tauri's distDir with zero bundler. If
// this ever needs to grow into something more complex (state
// management, routing), that's the point to introduce a real
// frontend framework — not before.

const invoke = window.__TAURI__ ? window.__TAURI__.invoke : null;

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
let processSortKey = "pid";
let processSortAsc = true;

async function refreshProcesses() {
  setConnectionStatus("loading");
  try {
    currentProcesses = await callBackend("list_processes");
    renderProcessTable();
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
  const body = document.getElementById("alert-table-body");
  body.innerHTML = "";

  if (!alerts || alerts.length === 0) {
    body.innerHTML = '<tr><td colspan="4" class="empty-row">No alerts.</td></tr>';
    return;
  }

  // Newest first.
  const sorted = [...alerts].sort((a, b) => (a.timestamp < b.timestamp ? 1 : -1));

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

// ---------- Utilities ----------

function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value;
  return div.innerHTML;
}

// ---------- Wire it all up ----------

document.addEventListener("DOMContentLoaded", () => {
  setupNav();
  setupProcessTableSorting();

  document.getElementById("refresh-dashboard").addEventListener("click", refreshDashboard);
  document.getElementById("refresh-processes").addEventListener("click", refreshProcesses);
  document.getElementById("process-search").addEventListener("input", renderProcessTable);
  document.getElementById("scan-now").addEventListener("click", scanNow);
  document.getElementById("load-alert-history").addEventListener("click", loadAlertHistory);

  // Initial load.
  refreshDashboard();
});
