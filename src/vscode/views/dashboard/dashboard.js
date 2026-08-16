// @ts-check
// SecureShield Dashboard — Client-side script
// Communicates with the VS Code extension via acquireVsCodeApi()

(function () {
  "use strict";

  // VS Code API for postMessage communication
  const vscode = acquireVsCodeApi();

  // ── State ───────────────────────────────────────────────────────────────────

  /** @type {{ findings: any[], history: any[], stats: any, dbHealth: any, gitHookInstalled: boolean }} */
  let state = {
    findings: [],
    history: [],
    stats: {
      totalDetected: 0,
      totalFixed: 0,
      totalSuppressed: 0,
      commitsBlocked: 0,
      byType: {},
      bySeverity: {},
      byFile: {},
    },
    dbHealth: null,
    gitHookInstalled: false,
  };

  let filterSeverity = "all";

  // ── DOM references ──────────────────────────────────────────────────────────

  const el = (/** @type {string} */ id) => document.getElementById(id);

  // ── Event listeners ─────────────────────────────────────────────────────────

  document.addEventListener("DOMContentLoaded", () => {
    bindButtons();
    bindFilter();
    requestInitialData();
  });

  function bindButtons() {
    const btnScan = el("btnScanWorkspace");
    const btnExport = el("btnExportReport");
    const btnClearHistory = el("btnClearHistory");
    const btnInstallHook = el("btnInstallHook");
    const btnRemoveHook = el("btnRemoveHook");

    if (btnScan) {
      btnScan.addEventListener("click", () => {
        postCommand("scanWorkspace");
        btnScan.textContent = "Scanning...";
        btnScan.setAttribute("disabled", "true");
        setTimeout(() => {
          btnScan.textContent = "Scan Workspace";
          btnScan.removeAttribute("disabled");
        }, 3000);
      });
    }

    if (btnExport) {
      btnExport.addEventListener("click", () => postCommand("exportReport"));
    }

    if (btnClearHistory) {
      btnClearHistory.addEventListener("click", () => {
        if (confirm("Clear all detection history and statistics?")) {
          postCommand("clearHistory");
        }
      });
    }

    if (btnInstallHook) {
      btnInstallHook.addEventListener("click", () =>
        postCommand("installGitHook"),
      );
    }

    if (btnRemoveHook) {
      btnRemoveHook.addEventListener("click", () => {
        if (confirm("Remove the SecureShield Git pre-commit hook?")) {
          postCommand("removeGitHook");
        }
      });
    }
  }

  function bindFilter() {
    const filterEl = el("filterSeverity");
    if (filterEl) {
      filterEl.addEventListener("change", (e) => {
        filterSeverity = /** @type {HTMLSelectElement} */ (e.target).value;
        renderFindingsTable();
      });
    }
  }

  function requestInitialData() {
    postCommand("requestData");
  }

  // ── Message handler from extension ─────────────────────────────────────────

  window.addEventListener("message", (event) => {
    const message = event.data;
    if (!message || !message.type) return;

    switch (message.type) {
      case "updateData":
        handleUpdateData(message.payload);
        break;
      case "updateFindings":
        state.findings = message.payload ?? [];
        renderFindingsTable();
        renderStatusBanner();
        renderSeverityGrid();
        break;
      case "updateStats":
        state.stats = message.payload ?? state.stats;
        renderStatsGrid();
        renderTypesGrid();
        break;
      case "updateHistory":
        state.history = message.payload ?? [];
        renderHistoryTable();
        break;
      case "updateGitHook":
        state.gitHookInstalled = message.payload === true;
        renderGitStatus();
        break;
      case "updateDbHealth":
        state.dbHealth = message.payload;
        renderDbHealth();
        break;
      default:
        break;
    }

    updateLastUpdated();
  });

  /** @param {any} payload */
  function handleUpdateData(payload) {
    if (!payload) return;
    if (payload.findings) state.findings = payload.findings;
    if (payload.history) state.history = payload.history;
    if (payload.stats) state.stats = payload.stats;
    if (payload.dbHealth) state.dbHealth = payload.dbHealth;
    if (typeof payload.gitHookInstalled === "boolean") {
      state.gitHookInstalled = payload.gitHookInstalled;
    }
    renderAll();
  }

  // ── Render functions ────────────────────────────────────────────────────────

  function renderAll() {
    renderStatusBanner();
    renderStatsGrid();
    renderSeverityGrid();
    renderFindingsTable();
    renderTypesGrid();
    renderHistoryTable();
    renderGitStatus();
    renderDbHealth();
    updateLastUpdated();
  }

  function renderStatusBanner() {
    const activeFindings = state.findings.filter((f) => !f.isFixed);
    const banner = el("statusBanner");
    const icon = el("statusIcon");
    const title = el("statusTitle");
    const subtitle = el("statusSubtitle");

    if (!banner || !icon || !title || !subtitle) return;

    banner.className = "ss-status-banner";

    if (activeFindings.length === 0) {
      banner.classList.add("is-clean");
      icon.className = "ss-indicator-dot ss-indicator-dot--success";
      title.textContent = "Your workspace is clean";
      subtitle.textContent = "No active secrets detected";
    } else {
      const hasCritical = activeFindings.some((f) => f.severity === "critical");
      const hasHigh = activeFindings.some((f) => f.severity === "high");

      if (hasCritical) {
        banner.classList.add("is-error");
        icon.className = "ss-indicator-dot ss-indicator-dot--error";
        title.textContent = `${activeFindings.length} Critical Secret(s) Detected`;
        subtitle.textContent =
          "Immediate action required — secrets must not be committed";
      } else if (hasHigh) {
        banner.classList.add("is-warning");
        icon.className = "ss-indicator-dot ss-indicator-dot--warning";
        title.textContent = `${activeFindings.length} Secret(s) Detected`;
        subtitle.textContent = "High-risk credentials found in your code";
      } else {
        banner.classList.add("is-warning");
        icon.className = "ss-indicator-dot ss-indicator-dot--warning";
        title.textContent = `${activeFindings.length} Potential Secret(s) Found`;
        subtitle.textContent = "Review the findings below and apply fixes";
      }
    }
  }

  function renderStatsGrid() {
    const s = state.stats;
    setText("statTotal", s.totalDetected ?? 0);
    setText("statFixed", s.totalFixed ?? 0);
    setText(
      "statActive",
      (s.totalDetected ?? 0) - (s.totalFixed ?? 0) - (s.totalSuppressed ?? 0),
    );
    setText("statSuppressed", s.totalSuppressed ?? 0);
    setText("statBlocked", s.commitsBlocked ?? 0);
  }

  function renderSeverityGrid() {
    const bySev = state.stats.bySeverity ?? {};
    setText("sevCritical", bySev["critical"] ?? 0);
    setText("sevHigh", bySev["high"] ?? 0);
    setText("sevMedium", bySev["medium"] ?? 0);
    setText("sevLow", bySev["low"] ?? 0);
    setText("sevInfo", bySev["informational"] ?? 0);
  }

  function renderFindingsTable() {
    const tbody = el("findingsTableBody");
    if (!tbody) return;

    const filtered =
      filterSeverity === "all"
        ? state.findings
        : state.findings.filter((f) => f.severity === filterSeverity);

    if (filtered.length === 0) {
      tbody.innerHTML = `
        <tr class="ss-table__empty-row">
          <td colspan="6">
            <div class="ss-empty-state">
              <span class="ss-empty-state__icon ss-indicator-dot ss-indicator-dot--neutral"></span>
              <p>${filterSeverity === "all" ? "No active findings" : `No ${filterSeverity} findings`}</p>
            </div>
          </td>
        </tr>`;
      return;
    }

    tbody.innerHTML = filtered
      .map((f) => {
        const sev = String(f.severity ?? "informational");
        const conf =
          typeof f.confidence === "object" ? (f.confidence.finalScore ?? 0) : 0;
        const confPct = Math.round(conf * 100);
        const fileName = String(f.meta?.fileName ?? "unknown");
        const line = (f.candidate?.lineNumber ?? 0) + 1;
        const typeStr = String(
          f.detection?.matchedRuleName ??
            f.detection?.matchedGroup ??
            "Unknown",
        );
        const envKey = String(f.remediation?.suggestedEnvKey ?? "SECRET");
        const findingId = String(f.id ?? "");

        return `
        <tr>
          <td><span class="ss-badge ss-badge--${escHtml(sev)}">${escHtml(sev.toUpperCase())}</span></td>
          <td><span class="ss-mono">${escHtml(fileName)}</span></td>
          <td>${escHtml(String(line))}</td>
          <td>${escHtml(typeStr)}</td>
          <td>
            <div class="ss-confidence">
              <div class="ss-confidence__bar">
                <div class="ss-confidence__fill ss-confidence__fill--${escHtml(sev)}"
                     style="width:${confPct}%"></div>
              </div>
              <span class="ss-confidence__label">${confPct}%</span>
            </div>
          </td>
          <td>
            <button class="ss-action-btn" onclick="fixFinding('${escHtml(findingId)}')">Fix</button>
            <button class="ss-action-btn" onclick="markSafe('${escHtml(findingId)}')">Safe</button>
          </td>
        </tr>`;
      })
      .join("");
  }

  function renderTypesGrid() {
    const grid = el("typesGrid");
    if (!grid) return;

    const byType = state.stats.byType ?? {};
    const entries = Object.entries(byType).sort(
      (a, b) => Number(b[1]) - Number(a[1]),
    );

    if (entries.length === 0) {
      grid.innerHTML = `
        <div class="ss-empty-state">
          <span class="ss-empty-state__icon ss-indicator-dot ss-indicator-dot--neutral"></span>
          <p>No data yet</p>
        </div>`;
      return;
    }

    grid.innerHTML = entries
      .map(
        ([type, count]) => `
      <div class="ss-type-card">
        <div class="ss-type-card__count">${escHtml(String(count))}</div>
        <div class="ss-type-card__name">${escHtml(String(type))}</div>
      </div>`,
      )
      .join("");
  }

  function renderHistoryTable() {
    const tbody = el("historyTableBody");
    if (!tbody) return;

    const recent = (state.history ?? []).slice(0, 50);

    if (recent.length === 0) {
      tbody.innerHTML = `
        <tr class="ss-table__empty-row">
          <td colspan="5">
            <div class="ss-empty-state">
              <span class="ss-empty-state__icon ss-indicator-dot ss-indicator-dot--neutral"></span>
              <p>No history yet</p>
            </div>
          </td>
        </tr>`;
      return;
    }

    tbody.innerHTML = recent
      .map((r) => {
        const sev = String(r.severity ?? "informational");
        const date = formatDate(r.detectedAt);
        const fileName = String(r.fileName ?? "unknown");
        const typeStr = String(r.ruleId ?? r.matchedGroup ?? "Unknown");
        const status = r.isFixed ? "fixed" : "active";

        return `
        <tr>
          <td>${escHtml(date)}</td>
          <td><span class="ss-mono">${escHtml(fileName)}</span></td>
          <td><span class="ss-badge ss-badge--${escHtml(sev)}">${escHtml(sev.toUpperCase())}</span></td>
          <td>${escHtml(typeStr)}</td>
          <td><span class="ss-badge ss-badge--${escHtml(status)}">${escHtml(status.toUpperCase())}</span></td>
        </tr>`;
      })
      .join("");
  }

  function renderGitStatus() {
    const icon = el("gitIcon");
    const label = el("gitLabel");
    const btnInstall = el("btnInstallHook");
    const btnRemove = el("btnRemoveHook");

    if (!icon || !label) return;

    if (state.gitHookInstalled) {
      icon.className = "ss-indicator-dot ss-indicator-dot--success";
      label.textContent =
        "Git pre-commit hook is active — commits will be scanned";
      if (btnInstall) btnInstall.style.display = "none";
      if (btnRemove) btnRemove.style.display = "inline-flex";
    } else {
      icon.className = "ss-indicator-dot ss-indicator-dot--neutral";
      label.textContent = "Git pre-commit hook not installed";
      if (btnInstall) btnInstall.style.display = "inline-flex";
      if (btnRemove) btnRemove.style.display = "none";
    }
  }

  function renderDbHealth() {
    const health = state.dbHealth;
    if (!health) return;

    const db1Status = el("db1Status");
    const db1Detail = el("db1Detail");
    const db2Status = el("db2Status");
    const db2Detail = el("db2Detail");

    if (db1Status && db1Detail) {
      if (health.db1?.loaded) {
        db1Status.textContent = "Loaded";
        db1Status.style.color = "var(--ss-success)";
        db1Detail.textContent = `${health.db1.ruleCount ?? 0} rules`;
      } else {
        db1Status.textContent = "Error";
        db1Status.style.color = "var(--ss-error)";
        db1Detail.textContent = health.db1?.error ?? "Unknown error";
      }
    }

    if (db2Status && db2Detail) {
      if (health.db2?.loaded) {
        db2Status.textContent = "Loaded";
        db2Status.style.color = "var(--ss-success)";
        db2Detail.textContent = `${health.db2.keywordCount ?? 0} identifiers`;
      } else {
        db2Status.textContent = "Error";
        db2Status.style.color = "var(--ss-error)";
        db2Detail.textContent = health.db2?.error ?? "Unknown error";
      }
    }
  }

  function updateLastUpdated() {
    const el_ = el("lastUpdated");
    if (el_) {
      el_.textContent = new Date().toLocaleTimeString();
    }
  }

  // ── Global action functions (called from onclick in table) ──────────────────

  /** @param {string} findingId */
  window.fixFinding = function (findingId) {
    postCommand("fixFinding", { findingId });
  };

  /** @param {string} findingId */
  window.markSafe = function (findingId) {
    postCommand("markSafe", { findingId });
  };

  // ── Helpers ─────────────────────────────────────────────────────────────────

  /**
   * @param {string} command
   * @param {any} [payload]
   */
  function postCommand(command, payload) {
    vscode.postMessage({ command, payload });
  }

  /**
   * @param {string} id
   * @param {string|number} value
   */
  function setText(id, value) {
    const element = el(id);
    if (element) element.textContent = String(value);
  }

  /** @param {string} str */
  function escHtml(str) {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  /** @param {string|Date} dateVal */
  function formatDate(dateVal) {
    try {
      const d = new Date(dateVal);
      return d.toLocaleDateString() + " " + d.toLocaleTimeString();
    } catch {
      return String(dateVal);
    }
  }
})();
