/**
 * popup.js — BrowserShield Extension Popup Logic
 * ================================================
 * Handles all interactivity in popup.html:
 *   - Backend connection status check
 *   - Last scan result display (with live updates)
 *   - Dashboard link
 *   - Session stats from /api/incidents/stats
 */

const BACKEND = "http://127.0.0.1:5000";

// ── On popup open ─────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    checkBackendStatus();
    loadLastScan();
    loadStats();

    // FIX #5 — Listen for storage changes so popup updates in real-time
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area === "local" && changes.lastScan) {
            renderScanCard(changes.lastScan.newValue);
        }
    });

    document.getElementById("btnDashboard").addEventListener("click", openDashboard);
    document.getElementById("btnRefresh").addEventListener("click", () => {
        checkBackendStatus();
        loadLastScan();
        loadStats();
    });
});


// ── Check backend connection ──────────────────────────────────────────

async function checkBackendStatus() {
    const indicator    = document.getElementById("statusIndicator");
    const statusText   = document.getElementById("statusText");
    const statusVersion = document.getElementById("statusVersion");

    try {
        const res  = await fetch(`${BACKEND}/`, {
            signal:      AbortSignal.timeout(3000),
            mode:        "cors",
            credentials: "omit"
        });
        const data = await res.json();

        indicator.className      = "status-connected";
        statusText.textContent   = "Backend Connected";
        statusVersion.textContent = `v${data.version || "1.0"}`;

    } catch {
        indicator.className      = "status-disconnected";
        statusText.textContent   = "Backend Offline";
        statusVersion.textContent = "—";
    }
}


// ── Load last scan from chrome.storage ───────────────────────────────

function loadLastScan() {
    chrome.storage.local.get("lastScan", ({ lastScan }) => {
        renderScanCard(lastScan || null);
    });
}


// ── Render scan card (extracted so storage listener can reuse it) ─────

function renderScanCard(lastScan) {
    const card = document.getElementById("lastScanCard");

    if (!lastScan) {
        card.className = "scan-card empty";
        card.innerHTML = `<div class="no-scan">No scans yet this session</div>`;
        return;
    }

    const riskClass  = `risk-${lastScan.risk}`;
    card.className   = `scan-card ${riskClass}`;

    const val        = lastScan.value || "—";
    const dispVal    = val.length > 45 ? val.slice(0, 42) + "…" : val;
    const reason     = lastScan.reason || "—";
    const dispReason = reason.length > 60 ? reason.slice(0, 57) + "…" : reason;

    const time = lastScan.timestamp
        ? new Date(lastScan.timestamp).toLocaleTimeString("en-GB")
        : "—";

    card.innerHTML = `
        <div class="scan-row">
            <span class="scan-key">Type</span>
            <span class="scan-val"><span class="type-pill">${escHtml(lastScan.type)}</span></span>
        </div>
        <div class="scan-row">
            <span class="scan-key">Risk</span>
            <span class="scan-val">
                <span class="risk-pill ${lastScan.risk}">${(lastScan.risk || "").toUpperCase()}</span>
            </span>
        </div>
        <div class="scan-row">
            <span class="scan-key">Target</span>
            <span class="scan-val">${escHtml(dispVal)}</span>
        </div>
        <div class="scan-row">
            <span class="scan-key">Reason</span>
            <span class="scan-val">${escHtml(dispReason)}</span>
        </div>
        <div class="scan-row">
            <span class="scan-key">Time</span>
            <span class="scan-val">${time}</span>
        </div>
    `;
}


// ── Load stats from backend ───────────────────────────────────────────

async function loadStats() {
    try {
        const res   = await fetch(`${BACKEND}/api/incidents/stats`, {
            signal:      AbortSignal.timeout(3000),
            mode:        "cors",
            credentials: "omit"
        });
        const stats = await res.json();

        document.getElementById("countHigh").textContent   = stats.by_risk?.high   ?? 0;
        document.getElementById("countMedium").textContent = stats.by_risk?.medium ?? 0;
        document.getElementById("countLow").textContent    = stats.by_risk?.low    ?? 0;

    } catch {
        document.getElementById("countHigh").textContent   = "—";
        document.getElementById("countMedium").textContent = "—";
        document.getElementById("countLow").textContent    = "—";
    }
}


// ── Open dashboard in new tab ─────────────────────────────────────────

function openDashboard() {
    chrome.tabs.create({ url: `${BACKEND}/dashboard` });
}


// ── Escape HTML ───────────────────────────────────────────────────────

function escHtml(str) {
    return String(str || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}