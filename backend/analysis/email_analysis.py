import re

# ml_email_model imported lazily to avoid crash if model files missing
_ml_available = True
try:
    from analysis.ml_email_model import predict_email_probability
except Exception:
    _ml_available = False

# ─────────────────────────────────────────────
#  DETECTION CONFIG
# ─────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    # Urgency
    "urgent", "immediately", "action required", "response required",
    # Account threats
    "verify", "validate", "confirm", "authenticate", "update",
    "suspended", "locked", "disabled", "unusual activity",
    # Credential harvesting
    "login", "password", "username", "credentials", "sign in",
    # Financial
    "bank", "account", "transfer", "wire", "payment", "invoice",
    # Reward lures
    "winner", "prize", "reward", "congratulations", "selected",
    # Generic phishing
    "click here", "click below", "security", "alert"
]

SAFE_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "google.com", "microsoft.com", "apple.com", "amazon.com"
]


def _check_keywords(text):
    """Returns list of matched phishing keywords."""
    text = text.lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in text]


def _count_urls(body):
    """Counts total URLs and unique domains in email body."""
    urls    = re.findall(r"https?://[^\s\"'>]+", body)
    domains = set()
    for url in urls:
        match = re.search(r"https?://([^/\s]+)", url)
        if match:
            domains.add(match.group(1).lower())
    return len(urls), len(domains)


def _check_sender(sender, body, subject):
    """
    Detects sender domain mismatch and spoofing.
    Improved: checks if sender domain appears in URLs in the body,
    not just anywhere in the body text.
    """
    issues = []
    if not sender or "@" not in sender:
        return issues

    sender_domain = sender.split("@")[-1].lower().strip()

    # Extract domains from URLs in body
    body_url_domains = re.findall(r"https?://([^/\s\"'>]+)", body.lower())

    # Check if sender domain matches any URL domain in body
    domain_in_links = any(sender_domain in d for d in body_url_domains)

    if not domain_in_links and body_url_domains:
        issues.append(f"Sender domain '{sender_domain}' not matching link domains")

    # Check for display name spoofing: "PayPal <attacker@evil.com>"
    display_match = re.match(r"(.+?)\s*<.+?>", sender)
    if display_match:
        display_name = display_match.group(1).lower()
        for brand in ["paypal", "google", "apple", "microsoft", "amazon", "bank"]:
            if brand in display_name and brand not in sender_domain:
                issues.append(f"Display name spoofing detected: '{display_name}'")
                break

    # Check if sender uses suspicious free email for official-looking subject
    official_keywords = ["account", "bank", "security", "invoice", "payment"]
    subject_lower = subject.lower()
    if any(kw in subject_lower for kw in official_keywords):
        if sender_domain in ["gmail.com", "yahoo.com", "hotmail.com"]:
            issues.append(f"Official-looking subject from free email: {sender_domain}")

    return issues


def _check_html_tricks(body):
    """Detects common HTML obfuscation tricks in email body."""
    issues = []

    # Mismatched anchor text vs href
    anchors = re.findall(r'<a\s+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>', body, re.IGNORECASE)
    for href, text in anchors:
        if re.match(r"https?://", text.strip()) and text.strip() != href:
            issues.append("Anchor text URL differs from actual href")
            break

    # Hidden text / tiny font
    if re.search(r'font-size\s*:\s*[01]px', body, re.IGNORECASE):
        issues.append("Hidden text detected (tiny font size)")

    return issues


def analyze_email(subject, sender, body):
    """
    Full phishing analysis of an email.
    Returns: (risk_level: str, reason: str, details: dict)
    """
    subject = subject or ""
    sender  = sender  or ""
    body    = body    or ""

    full_text  = f"{subject} {body}"
    flags      = []
    score      = 0

    # ── Check 1: Suspicious keywords ─────────────────────────────────
    matched = _check_keywords(full_text)
    if matched:
        score += min(len(matched), 4)   # cap at 4 to avoid over-scoring
        flags.append(f"Phishing keywords: {', '.join(matched[:5])}")

    # ── Check 2: URL count analysis ───────────────────────────────────
    url_count, unique_domains = _count_urls(body)
    if url_count > 5:
        score += 2
        flags.append(f"Too many URLs in email body ({url_count})")
    elif url_count > 2:
        score += 1
        flags.append(f"Multiple URLs detected ({url_count})")

    if unique_domains > 3:
        score += 1
        flags.append(f"Links point to {unique_domains} different domains")

    # ── Check 3: Sender analysis ──────────────────────────────────────
    sender_issues = _check_sender(sender, body, subject)
    if sender_issues:
        score += len(sender_issues)
        flags.extend(sender_issues)

    # ── Check 4: HTML tricks ──────────────────────────────────────────
    html_issues = _check_html_tricks(body)
    if html_issues:
        score += len(html_issues) * 2
        flags.extend(html_issues)

    # ── Check 5: Urgency in subject line ─────────────────────────────
    urgency_patterns = [
        r"\bURGENT\b", r"\bIMMEDIATELY\b", r"!!+",
        r"verify now", r"act now", r"expires? (today|soon|in \d+)"
    ]
    for pattern in urgency_patterns:
        if re.search(pattern, subject, re.IGNORECASE):
            score += 1
            flags.append(f"Urgency pattern in subject: matched '{pattern}'")
            break

    # ── Check 6: ML model prediction ─────────────────────────────────
    ml_score = 0.0
    if _ml_available:
        try:
            ml_score = predict_email_probability(subject, body)
            if ml_score >= 0.80:
                score += 4
            elif ml_score >= 0.60:
                score += 2
            elif ml_score >= 0.40:
                score += 1
        except Exception:
            ml_score = 0.0

    # ── Final risk decision ───────────────────────────────────────────
    if score >= 6:
        risk = "high"
    elif score >= 3:
        risk = "medium"
    else:
        risk = "low"

    # Build human-readable reason
    reason = f"ML score: {ml_score:.2f}"
    if flags:
        reason += " | " + " | ".join(flags[:3])   # top 3 flags in reason
    if not flags and ml_score < 0.4:
        reason = "No phishing indicators detected"

    details = {
        "ml_score":       round(ml_score, 3),
        "rule_score":     score,
        "flags":          flags,
        "url_count":      url_count,
        "unique_domains": unique_domains
    }

    return risk, reason, details