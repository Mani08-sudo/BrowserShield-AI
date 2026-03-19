/**
 * content.js — BrowserShield Email Scanner
 * ==========================================
 * Injected into Gmail, Outlook, and Yahoo Mail.
 * Detects when the user opens an email and sends
 * the content to the background script for analysis.
 *
 * Supported webmail clients:
 *   - Gmail (mail.google.com)
 *   - Outlook Web (outlook.live.com, outlook.office.com)
 *   - Yahoo Mail (mail.yahoo.com)  ← FIX #4 added
 */

console.log("[BrowserShield] Content script loaded on:", window.location.hostname);

// ── State ─────────────────────────────────────────────────────────────
let lastAnalyzedSubject = "";
let warningBannerShown  = false;
let analysisTimeout     = null;


// ── Inject warning banner styles ──────────────────────────────────────
const style = document.createElement("style");
style.textContent = `
    #bs-warning-banner {
        position: fixed;
        top: 0; left: 0; right: 0;
        z-index: 999999;
        font-family: 'Segoe UI', Arial, sans-serif;
        font-size: 14px;
        padding: 14px 20px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.4);
        animation: bs-slide-down 0.3s ease;
    }

    @keyframes bs-slide-down {
        from { transform: translateY(-100%); opacity: 0; }
        to   { transform: translateY(0);     opacity: 1; }
    }

    #bs-warning-banner.high {
        background: #1a0505;
        border-bottom: 2px solid #ff4c4c;
        color: #ffaaaa;
    }

    #bs-warning-banner.medium {
        background: #1a1005;
        border-bottom: 2px solid #f5a623;
        color: #ffd580;
    }

    #bs-warning-banner .bs-icon   { font-size: 20px; flex-shrink: 0; }
    #bs-warning-banner .bs-text   { flex: 1; line-height: 1.4; }
    #bs-warning-banner .bs-title  { font-weight: 700; font-size: 15px; margin-bottom: 2px; }
    #bs-warning-banner .bs-reason { font-size: 12px; opacity: 0.8; }

    #bs-warning-banner .bs-close {
        background: rgba(255,255,255,0.1);
        border: none;
        color: inherit;
        padding: 6px 12px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 13px;
        font-family: inherit;
        flex-shrink: 0;
        transition: background 0.2s;
    }

    #bs-warning-banner .bs-close:hover { background: rgba(255,255,255,0.2); }
`;
document.head.appendChild(style);


// ── Show warning banner in page ───────────────────────────────────────

function showWarningBanner(risk, reason, subject) {
    removeWarningBanner();

    if (risk === "low") return;

    const banner = document.createElement("div");
    banner.id        = "bs-warning-banner";
    banner.className = risk;

    const icon  = risk === "high" ? "🚨" : "⚠️";
    const title = risk === "high"
        ? "BrowserShield: Phishing Email Detected"
        : "BrowserShield: Suspicious Email";

    banner.innerHTML = `
        <span class="bs-icon">${icon}</span>
        <div class="bs-text">
            <div class="bs-title">${title}</div>
            <div class="bs-reason">${escapeHtml(reason)}</div>
        </div>
        <button class="bs-close" id="bs-close-btn">Dismiss ✕</button>
    `;

    document.body.prepend(banner);
    document.getElementById("bs-close-btn").addEventListener("click", removeWarningBanner);

    if (risk === "medium") {
        setTimeout(removeWarningBanner, 10000);
    }

    warningBannerShown = true;
}


function removeWarningBanner() {
    const existing = document.getElementById("bs-warning-banner");
    if (existing) existing.remove();
    warningBannerShown = false;
}


function escapeHtml(str) {
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}


// ── Extract email content from Gmail ─────────────────────────────────

function extractGmailEmail() {
    const subjectEl = document.querySelector("h2[data-thread-perm-id], .hP");
    const subject   = subjectEl ? subjectEl.innerText.trim() : "";

    const senderEl  = document.querySelector(".gD");
    const sender    = senderEl ? (senderEl.getAttribute("email") || senderEl.innerText) : "";

    const bodyEl    = document.querySelector(".a3s.aiL");
    const body      = bodyEl ? bodyEl.innerText.trim() : "";

    return { subject, sender, body };
}


// ── Extract email content from Outlook ───────────────────────────────

function extractOutlookEmail() {
    const subjectEl = document.querySelector('[aria-label="Message subject"]') ||
                      document.querySelector('.SubjectReplyFwd');
    const subject   = subjectEl ? subjectEl.innerText.trim() : "";

    const senderEl  = document.querySelector('[aria-label*="From"]');
    const sender    = senderEl ? senderEl.innerText.trim() : "";

    const bodyEl    = document.querySelector('[aria-label="Message body"]') ||
                      document.querySelector('.ReadMsgBody');
    const body      = bodyEl ? bodyEl.innerText.trim() : "";

    return { subject, sender, body };
}


// ── FIX #4 — Extract email content from Yahoo Mail ───────────────────

function extractYahooEmail() {
    const subjectEl = document.querySelector('[data-test-id="message-group-subject-text"]') ||
                      document.querySelector('.rg.y2');
    const subject   = subjectEl ? subjectEl.innerText.trim() : "";

    const senderEl  = document.querySelector('[data-test-id="msg-from"] .zE') ||
                      document.querySelector('[data-test-id="msg-from"]');
    const sender    = senderEl ? senderEl.innerText.trim() : "";

    const bodyEl    = document.querySelector('[data-test-id="message-view-body-content"]') ||
                      document.querySelector('.ya-q-full-content');
    const body      = bodyEl ? bodyEl.innerText.trim() : "";

    return { subject, sender, body };
}


// ── Extract email based on current site ──────────────────────────────

function extractEmail() {
    const host = window.location.hostname;

    if (host.includes("mail.google.com"))  return extractGmailEmail();
    if (host.includes("outlook"))          return extractOutlookEmail();
    if (host.includes("yahoo.com"))        return extractYahooEmail();   // FIX #4

    return { subject: "", sender: "", body: "" };
}


// ── Analyze current email ─────────────────────────────────────────────

function analyzeCurrentEmail() {
    const { subject, sender, body } = extractEmail();

    if (!subject && !body)               return;
    if (subject === lastAnalyzedSubject) return;

    lastAnalyzedSubject = subject;

    console.log("[BrowserShield] Sending email for analysis:", subject.slice(0, 50));

    chrome.runtime.sendMessage(
        { type: "ANALYZE_EMAIL", subject, sender, body },
        (result) => {
            if (chrome.runtime.lastError) {
                console.warn("[BrowserShield] Message error:", chrome.runtime.lastError);
                return;
            }

            if (!result) return;

            console.log(`[BrowserShield] Email result: [${result.risk}]`, result.reason);

            if (result.risk === "high" || result.risk === "medium") {
                showWarningBanner(result.risk, result.reason, subject);
            } else {
                removeWarningBanner();
            }
        }
    );
}


// ── Watch for email opens via MutationObserver ────────────────────────

const observer = new MutationObserver(() => {
    clearTimeout(analysisTimeout);
    analysisTimeout = setTimeout(analyzeCurrentEmail, 800);
});

function startObserving() {
    observer.observe(document.body, {
        childList: true,
        subtree:   true
    });
    console.log("[BrowserShield] Email observer started");
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startObserving);
} else {
    startObserving();
}