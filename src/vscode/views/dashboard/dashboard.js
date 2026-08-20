// @ts-check
// Keymontr Dashboard — Client-side script
// Communicates with the VS Code extension via acquireVsCodeApi()

(function () {
  "use strict";

  const vscode = acquireVsCodeApi();

  // ── State ───────────────────────────────────────────────────────────────────

  /** @type {{ findings: any[], history: any[], stats: any, dbHealth: any, gitHookInstalled: boolean, ignoredKeys: any[], aiAgents: any[] }} */
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
    ignoredKeys: [],
    aiAgents: [],
  };

  let filterSeverity = "all";
  let filterQuery = "";

  const SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"];
  const SEVERITY_COLORS = {
    critical: "var(--sev-critical)",
    high: "var(--sev-high)",
    medium: "var(--sev-medium)",
    low: "var(--sev-low)",
    informational: "var(--sev-info)",
  };

  const el = (/** @type {string} */ id) => document.getElementById(id);

  // ── Init ────────────────────────────────────────────────────────────────────

  document.addEventListener("DOMContentLoaded", () => {
    bindButtons();
    bindFilters();
    bindNav();
    bindSearchShortcuts();
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
        btnScan.disabled = true;
        btnScan.lastChild.textContent = " Scanning…";
        setTimeout(() => {
          btnScan.disabled = false;
          btnScan.lastChild.textContent = " Scan Workspace";
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
      btnInstallHook.addEventListener("click", () => postCommand("installGitHook"));
    }

    if (btnRemoveHook) {
      btnRemoveHook.addEventListener("click", () => {
        if (confirm("Remove the Keymontr Git pre-commit hook?")) {
          postCommand("removeGitHook");
        }
      });
    }
  }

  function bindFilters() {
    const filterEl = el("filterSeverity");
    if (filterEl) {
      filterEl.addEventListener("change", (e) => {
        filterSeverity = /** @type {HTMLSelectElement} */ (e.target).value;
        renderFindingsTable();
      });
    }

    const searchEl = el("searchInput");
    if (searchEl) {
      searchEl.addEventListener("input", (e) => {
        filterQuery = /** @type {HTMLInputElement} */ (e.target).value.trim().toLowerCase();
        renderFindingsTable();
      });
    }
  }

  function bindNav() {
    const nav = el("sidebarNav");
    if (!nav) return;

    const links = Array.from(nav.querySelectorAll(".km-nav__item"));
    const setActive = (href) => {
      links.forEach((link) =>
        link.classList.toggle("is-active", link.getAttribute("href") === href),
      );
    };

    links.forEach((link) =>
      link.addEventListener("click", () => setActive(link.getAttribute("href"))),
    );

    const sections = ["overview", "findings", "ignored", "history"]
      .map((id) => el(id))
      .filter(Boolean);

    if (sections.length && "IntersectionObserver" in window) {
      const observer = new IntersectionObserver(
        (entries) => {
          const visible = entries.filter((entry) => entry.isIntersecting);
          if (visible.length) setActive("#" + visible[0].target.id);
        },
        { rootMargin: "-40% 0px -55% 0px" },
      );
      sections.forEach((section) => observer.observe(section));
    }
  }

  function bindSearchShortcuts() {
    document.addEventListener("keydown", (event) => {
      const search = el("searchInput");
      if (!search) return;
      const mod = event.ctrlKey || event.metaKey;
      const isShortcut = mod && event.key.toLowerCase() === "k";
      const isSlash = event.key === "/" && document.activeElement !== search;
      if (isShortcut || isSlash) {
        event.preventDefault();
        search.focus();
      } else if (event.key === "Escape" && document.activeElement === search) {
        search.blur();
      }
    });
  }

  function requestInitialData() {
    postCommand("requestData");
  }

  // ── Message handler ─────────────────────────────────────────────────────────

  window.addEventListener("message", (event) => {
    const message = event.data;
    if (!message || !message.type) return;

    switch (message.type) {
      case "updateData":
        handleUpdateData(message.payload);
        break;
      case "updateGitHook":
        state.gitHookInstalled = message.payload === true;
        renderGitStatus();
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
    if (Array.isArray(payload.ignoredKeys)) {
      state.ignoredKeys = payload.ignoredKeys;
    }
    if (Array.isArray(payload.aiAgents)) {
      state.aiAgents = payload.aiAgents;
    }
    renderAll();
  }

  // ── Render entry ────────────────────────────────────────────────────────────

  function renderAll() {
    renderStatus();
    renderStats();
    renderDonutChart();
    renderFindingsTable();
    renderTypesBars();
    renderIgnoredKeys();
    renderHistoryTable();
    renderSparkline();
    renderGitStatus();
    renderDbHealth();
    renderAIAgents();
    updateLastUpdated();
  }

  // ── Status banner + header pill ─────────────────────────────────────────────

  function renderStatus() {
    const active = state.findings.filter((f) => !f.isFixed);
    const hero = el("statusHero");
    const icon = el("statusIcon");
    const title = el("statusTitle");
    const subtitle = el("statusSubtitle");
    const pill = el("headerStatusPill");
    const pillText = el("headerStatusText");

    if (!hero || !icon || !title || !subtitle) return;

    hero.classList.remove("is-clean", "is-warning", "is-error");

    if (active.length === 0) {
      hero.classList.add("is-clean");
      title.textContent = "Your workspace is clean";
      subtitle.textContent = "No active secrets detected";
      if (pill) {
        pill.className = "km-status-pill km-status-pill--clean";
        pillText.textContent = "Clean";
      }
      return;
    }

    const hasCritical = active.some((f) => f.severity === "critical");
    const hasHigh = active.some((f) => f.severity === "high");

    if (hasCritical) {
      hero.classList.add("is-error");
      title.textContent = `${active.length} active secret${active.length === 1 ? "" : "s"} — immediate action required`;
      subtitle.textContent = "Critical credentials found in your code. Fix or suppress before committing.";
      if (pill) {
        pill.className = "km-status-pill km-status-pill--risk";
        pillText.textContent = `${active.length} at risk`;
      }
    } else if (hasHigh) {
      hero.classList.add("is-warning");
      title.textContent = `${active.length} active secret${active.length === 1 ? "" : "s"} detected`;
      subtitle.textContent = "High-risk credentials found in your code. Review the findings below.";
      if (pill) {
        pill.className = "km-status-pill km-status-pill--warn";
        pillText.textContent = `${active.length} at risk`;
      }
    } else {
      hero.classList.add("is-warning");
      title.textContent = `${active.length} potential secret${active.length === 1 ? "" : "s"} found`;
      subtitle.textContent = "Review the findings below and apply fixes.";
      if (pill) {
        pill.className = "km-status-pill km-status-pill--warn";
        pillText.textContent = `${active.length} to review`;
      }
    }
  }

  // ── Stats cards + hero chips ────────────────────────────────────────────────

  function renderStats() {
    const s = state.stats;
    const total = s.totalDetected ?? 0;
    const fixed = s.totalFixed ?? 0;
    const blocked = s.commitsBlocked ?? 0;

    // "Active" reflects the CURRENT state (live findings / current ignores),
    // matching the sidebar. Lifetime counters (total/fixed/blocked) come
    // from statistics.
    const active = state.findings.filter((f) => !f.isFixed).length;
    const suppressed = (state.ignoredKeys ?? []).length;

    setText("statTotal", total);
    setText("statFixed", fixed);
    setText("statActive", active);
    setText("statSuppressed", suppressed);
    setText("statBlocked", blocked);

    setText("heroActive", active);
    setText("heroFixed", fixed);
    setText("heroSuppressed", suppressed);
    setText("heroBlocked", blocked);
  }

  // ── Donut chart (risk distribution) ─────────────────────────────────────────

  function renderDonutChart() {
    const svg = el("donutSvg");
    const legend = el("donutLegend");
    const totalEl = el("donutTotal");
    if (!svg || !legend) return;

    // Risk distribution reflects the CURRENT live findings so the donut
    // matches the sidebar (not the lifetime statistics).
    const bySev = {};
    for (const f of state.findings) {
      const sev = String(f.severity ?? "informational");
      bySev[sev] = (bySev[sev] ?? 0) + 1;
    }
    const total = SEVERITY_ORDER.reduce((sum, s) => sum + (bySev[s] ?? 0), 0);

    if (totalEl) totalEl.textContent = String(total);

    const R = 50;
    const CIRC = 2 * Math.PI * R;
    const GAP = 2.5;

    let svgInner = "";
    let offset = 0;
    let hasSegments = false;

    for (const sev of SEVERITY_ORDER) {
      const count = bySev[sev] ?? 0;
      if (count <= 0) continue;
      hasSegments = true;
      const len = Math.max((count / total) * CIRC - GAP, 0.5);
      svgInner += `<circle cx="60" cy="60" r="${R}" fill="none" stroke="${SEVERITY_COLORS[sev]}"
        stroke-width="13" stroke-linecap="butt"
        stroke-dasharray="${len.toFixed(2)} ${(CIRC - len).toFixed(2)}"
        stroke-dashoffset="${(-offset).toFixed(2)}" />`;
      offset += len + GAP;
    }

    svg.innerHTML =
      `<circle cx="60" cy="60" r="${R}" fill="none" stroke="var(--border-soft)" stroke-width="13" />` +
      svgInner;

    // Legend
    const entries = SEVERITY_ORDER.filter((sev) => (bySev[sev] ?? 0) > 0);
    if (entries.length === 0) {
      legend.innerHTML = `<div class="km-empty">No findings yet</div>`;
      return;
    }

    legend.innerHTML = entries
      .map((sev) => {
        const count = bySev[sev] ?? 0;
        const pct = total > 0 ? Math.round((count / total) * 100) : 0;
        return `
        <div class="km-legend__row">
          <span class="km-legend__swatch" style="background:${SEVERITY_COLORS[sev]}"></span>
          <span class="km-legend__label">${sev}</span>
          <span class="km-legend__count">${count}</span>
          <span class="km-legend__pct">${pct}%</span>
        </div>`;
      })
      .join("");
  }

  // ── Bar chart (secret types) ────────────────────────────────────────────────

  function renderTypesBars() {
    const bars = el("typesBars");
    const countEl = el("typesCount");
    if (!bars) return;

    // Secret types reflect the CURRENT live findings (consistent with the
    // risk distribution), not the lifetime statistics.
    const byType = {};
    for (const f of state.findings) {
      const type = String(
        f.detection?.matchedRuleId ?? f.detection?.matchedGroup ?? "unknown",
      );
      byType[type] = (byType[type] ?? 0) + 1;
    }
    const entries = Object.entries(byType)
      .sort((a, b) => Number(b[1]) - Number(a[1]))
      .slice(0, 8);

    if (countEl) {
      countEl.textContent = `${Object.keys(byType).length} type${Object.keys(byType).length === 1 ? "" : "s"}`;
    }

    if (entries.length === 0) {
      bars.innerHTML = `<div class="km-empty">No secrets detected yet</div>`;
      return;
    }

    const max = Math.max(...entries.map(([, c]) => Number(c)), 1);

    bars.innerHTML = entries
      .map(([type, count]) => {
        const pct = Math.round((Number(count) / max) * 100);
        return `
        <div class="km-bar-row">
          <span class="km-bar-row__label" title="${escHtml(String(type))}">${escHtml(String(type))}</span>
          <div class="km-bar-row__track">
            <div class="km-bar-row__fill" style="width:${pct}%"></div>
          </div>
          <span class="km-bar-row__count">${escHtml(String(count))}</span>
        </div>`;
      })
      .join("");
  }

  // ── Findings table ──────────────────────────────────────────────────────────

  function renderFindingsTable() {
    const tbody = el("findingsTableBody");
    const countEl = el("findingsCount");
    if (!tbody) return;

    let filtered = state.findings;
    if (filterSeverity !== "all") {
      filtered = filtered.filter((f) => f.severity === filterSeverity);
    }
    if (filterQuery) {
      filtered = filtered.filter((f) => {
        const fileName = String(f.meta?.fileName ?? "").toLowerCase();
        const type = String(
          f.detection?.matchedRuleName ?? f.detection?.matchedGroup ?? "",
        ).toLowerCase();
        return fileName.includes(filterQuery) || type.includes(filterQuery);
      });
    }

    if (countEl) {
      countEl.textContent = `${filtered.length} finding${filtered.length === 1 ? "" : "s"}`;
    }

    if (filtered.length === 0) {
      tbody.innerHTML = `
        <tr class="km-table__empty">
          <td colspan="5">
            <div class="km-empty">${
              state.findings.length === 0
                ? "No active findings"
                : "No findings match the current filter"
            }</div>
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

        return `
        <tr>
          <td><span class="km-badge km-badge--${escHtml(sev)}">${escHtml(sev)}</span></td>
          <td><span class="km-mono">${escHtml(fileName)}</span></td>
          <td>${escHtml(String(line))}</td>
          <td>${escHtml(typeStr)}</td>
          <td>
            <div class="km-confidence">
              <div class="km-confidence__track">
                <div class="km-confidence__fill km-confidence__fill--${escHtml(sev)}"
                     style="width:${confPct}%"></div>
              </div>
              <span class="km-confidence__label">${confPct}%</span>
            </div>
          </td>
        </tr>`;
      })
      .join("");
  }

  // ── History table ───────────────────────────────────────────────────────────

  function renderHistoryTable() {
    const tbody = el("historyTableBody");
    if (!tbody) return;

    const recent = (state.history ?? []).slice(0, 50);

    if (recent.length === 0) {
      tbody.innerHTML = `
        <tr class="km-table__empty">
          <td colspan="5"><div class="km-empty">No history yet</div></td>
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
          <td><span class="km-mono">${escHtml(fileName)}</span></td>
          <td><span class="km-badge km-badge--${escHtml(sev)}">${escHtml(sev)}</span></td>
          <td>${escHtml(typeStr)}</td>
          <td><span class="km-badge km-badge--${escHtml(status)}">${escHtml(status)}</span></td>
        </tr>`;
      })
      .join("");
  }

  // ── Sparkline (detections over last 14 days) ────────────────────────────────

  function renderSparkline() {
    const svg = el("sparklineSvg");
    const emptyEl = el("sparklineEmpty");
    const hintEl = el("sparklineHint");
    if (!svg || !emptyEl) return;

    const history = state.history ?? [];
    if (history.length === 0) {
      svg.innerHTML = "";
      svg.style.display = "none";
      emptyEl.style.display = "flex";
      return;
    }
    svg.style.display = "block";
    emptyEl.style.display = "none";

    // Bucket detections per day for the last 14 days
    const days = 14;
    const buckets = new Array(days).fill(0);
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    for (const r of history) {
      const t = new Date(r.detectedAt ?? Date.now());
      const dayStart = new Date(t);
      dayStart.setHours(0, 0, 0, 0);
      const diffDays = Math.round((today.getTime() - dayStart.getTime()) / 86400000);
      if (diffDays >= 0 && diffDays < days) {
        buckets[days - 1 - diffDays] += 1;
      }
    }

    const W = 280;
    const H = 96;
    const PAD = 6;
    const max = Math.max(...buckets, 1);
    const stepX = (W - PAD * 2) / (days - 1);
    const points = buckets.map((count, i) => {
      const x = PAD + i * stepX;
      const y = H - PAD - (count / max) * (H - PAD * 2 - 8);
      return { x, y, count };
    });

    const linePath = points
      .map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(1)},${p.y.toFixed(1)}`)
      .join(" ");
    const areaPath =
      `${linePath} L${points[points.length - 1].x.toFixed(1)},${H - PAD} ` +
      `L${points[0].x.toFixed(1)},${H - PAD} Z`;

    const last = points[points.length - 1];
    const peak = points.reduce((a, b) => (b.count > a.count ? b : a), points[0]);

    svg.innerHTML = `
      <defs>
        <linearGradient id="kmArea" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--primary)" stop-opacity="0.35" />
          <stop offset="100%" stop-color="var(--primary)" stop-opacity="0.02" />
        </linearGradient>
      </defs>
      <path d="${areaPath}" fill="url(#kmArea)" />
      <path d="${linePath}" fill="none" stroke="var(--primary)" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round" />
      <circle cx="${peak.x.toFixed(1)}" cy="${peak.y.toFixed(1)}" r="3.5"
              fill="var(--primary)" stroke="var(--card)" stroke-width="1.5" />
      <text x="${W - PAD}" y="${H - 4}" text-anchor="end" font-size="9"
            fill="var(--muted)" font-family="var(--font)">${last.count} today</text>`;

    if (hintEl) {
      const daysWithData = buckets.filter((b) => b > 0).length;
      hintEl.textContent = `${daysWithData} active day${daysWithData === 1 ? "" : "s"} · last 14 days`;
    }
  }

  // ── Ignored keys ─────────────────────────────────────────────────────────────

  function renderIgnoredKeys() {
    const tbody = el("ignoredTableBody");
    const countEl = el("ignoredCount");
    if (!tbody) return;

    const keys = state.ignoredKeys ?? [];

    if (countEl) {
      countEl.textContent = `${keys.length} ignored`;
    }

    if (keys.length === 0) {
      tbody.innerHTML = `
        <tr class="km-table__empty">
          <td colspan="6"><div class="km-empty">No ignored keys</div></td>
        </tr>`;
      return;
    }

    tbody.innerHTML = keys
      .map((k) => {
        const sev = String(k.severity ?? "informational");
        const line = Number(k.lineNumber ?? 0) + 1;
        const ruleName = String(k.ruleName ?? "—");
        const reason = String(k.reason ?? "—");
        const kind = k.kind === "session" ? "session" : "permanent";
        const kindLabel = kind === "session" ? "Session" : "Permanent";
        return `
        <tr>
          <td><span class="km-mono">${escHtml(String(k.fileName ?? "unknown"))}</span></td>
          <td>${escHtml(String(line))}</td>
          <td><span class="km-badge km-badge--${escHtml(sev)}">${escHtml(sev)}</span></td>
          <td>${escHtml(ruleName)}</td>
          <td><span class="km-badge km-badge--soft">${escHtml(kindLabel)}</span> ${escHtml(reason)}</td>
          <td>${escHtml(formatDate(k.ignoredAt))}</td>
        </tr>`;
      })
      .join("");
  }

  // ── AI assistants ─────────────────────────────────────────────────────────────

  function renderAIAgents() {
    const list = el("aiList");
    const countEl = el("aiCount");
    if (!list) return;

    const agents = (state.aiAgents ?? []).filter((a) => a.installed);

    if (countEl) {
      const activeCount = agents.filter((a) => a.active).length;
      countEl.textContent = `${activeCount} active`;
    }

    if (agents.length === 0) {
      list.innerHTML = `<div class="km-empty km-empty--compact">None detected</div>`;
      return;
    }

    list.innerHTML = agents
      .map((agent) => {
        const name = String(agent.name ?? agent.id ?? "Unknown");
        const vendor = agent.vendor ? String(agent.vendor) : "";
        return `
        <div class="km-ai__row">
          <span class="km-ai__dot ${agent.active ? "km-ai__dot--active" : ""}"></span>
          <div class="km-ai__info">
            <span class="km-ai__name">${escHtml(name)}</span>
            ${vendor ? `<span class="km-ai__meta">${escHtml(vendor)}</span>` : ""}
          </div>
          <span class="km-ai__tag ${agent.active ? "km-ai__tag--active" : ""}">${
            agent.active ? "Active" : "Installed"
          }</span>
        </div>`;
      })
      .join("");
  }

  // ── Git protection ──────────────────────────────────────────────────────────

  function renderGitStatus() {
    const icon = el("gitIcon");
    const label = el("gitLabel");
    const hint = el("gitStatusHint");
    const btnInstall = el("btnInstallHook");
    const btnRemove = el("btnRemoveHook");

    if (!icon || !label) return;

    if (state.gitHookInstalled) {
      icon.className = "km-dot km-dot--success";
      label.textContent = "Pre-commit hook active — commits are scanned";
      if (hint) hint.textContent = "Protected";
      if (btnInstall) btnInstall.style.display = "none";
      if (btnRemove) btnRemove.style.display = "inline-flex";
    } else {
      icon.className = "km-dot km-dot--neutral";
      label.textContent = "Pre-commit hook not installed";
      if (hint) hint.textContent = "Unprotected";
      if (btnInstall) btnInstall.style.display = "inline-flex";
      if (btnRemove) btnRemove.style.display = "none";
    }
  }

  // ── Database health ─────────────────────────────────────────────────────────

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
        db1Status.className = "km-badge km-badge--fixed";
        db1Detail.textContent = `${health.db1.ruleCount ?? 0} rules`;
      } else {
        db1Status.textContent = "Error";
        db1Status.className = "km-badge km-badge--danger";
        db1Detail.textContent = health.db1?.error ?? "Unknown error";
      }
    }

    if (db2Status && db2Detail) {
      if (health.db2?.loaded) {
        db2Status.textContent = "Loaded";
        db2Status.className = "km-badge km-badge--fixed";
        db2Detail.textContent = `${health.db2.keywordCount ?? 0} identifiers`;
      } else {
        db2Status.textContent = "Error";
        db2Status.className = "km-badge km-badge--danger";
        db2Detail.textContent = health.db2?.error ?? "Unknown error";
      }
    }
  }

  function updateLastUpdated() {
    const el_ = el("lastUpdated");
    if (el_) el_.textContent = new Date().toLocaleTimeString();
  }

  // ── Global action functions (called from onclick in table) ──────────────────
// (No actions in the findings table — ignore/fix are done from the editor.)

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