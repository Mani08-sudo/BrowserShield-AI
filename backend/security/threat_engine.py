"""
BrowserShield — Threat Scoring Engine
backend/security/threat_engine.py
"""

import re
import math
import unicodedata
from collections import Counter
import tldextract


# ═══════════════════════════════════════════════════════════════
# MAX SCORE
# ═══════════════════════════════════════════════════════════════

MAX_SCORE = 211
# Updated with new signals


# ─── Whitelisted domains ───────────────────────────────────────
SAFE_DOMAINS = {
    "google.com", "youtube.com", "github.com",
    "microsoft.com"
}


# ─── Suspicious TLDs ───────────────────────────────────────────
SUSPICIOUS_TLDS = {
    "xyz","top","cc","tk","ml","ga","gq","cf","pw",
    "click","link","live","vip"
}


# ─── URL shorteners ────────────────────────────────────────────
SHORTENERS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd"
}


# ─── Phishing keywords ─────────────────────────────────────────
PHISHING_WORDS = [
    "login","verify","secure","account","update",
    "bank","paypal","password","confirm","signin",
    "webscr","ebayisapi","reset","authorize"
]


# ─── Homograph map ─────────────────────────────────────────────
HOMOGRAPH_MAP = {
    "а":"a","е":"e","о":"o","р":"p",
    "с":"c","х":"x","у":"y","і":"i",
    "0":"o","1":"l","3":"e","5":"s",
    "6":"g","8":"b"
}


# ═══════════════════════════════════════════════════════════════
# DOMAIN HELPERS
# ═══════════════════════════════════════════════════════════════

def extract_domain(url):

    ext = tldextract.extract(url)

    if not ext.domain or not ext.suffix:
        return url

    return f"{ext.domain}.{ext.suffix}"


def is_safe_domain(url):
    return extract_domain(url) in SAFE_DOMAINS


# ═══════════════════════════════════════════════════════════════
# SIGNAL SCORERS
# ═══════════════════════════════════════════════════════════════

def ssl_score(url):
    return 8 if url.lower().startswith("http://") else 0


def keyword_score(url):
    normalised = re.sub(r"[/\-_.?=&+]", " ", url.lower())
    matched = [
        w for w in PHISHING_WORDS
        if re.search(rf"\b{re.escape(w)}\b", normalised)
    ]

    n = len(matched)

    if n == 0: return 0
    if n == 1: return 15
    if n == 2: return 23
    return min(23 + (n - 2) * 3, 30)


def tld_score(url):
    ext = tldextract.extract(url)
    tld = ext.suffix.split(".")[-1]
    return 16 if tld in SUSPICIOUS_TLDS else 0


def url_entropy_score(url):

    if not url:
        return 0

    score = 0
    n = len(url)

    if n > 120: score += 10
    elif n > 80: score += 5

    counts = Counter(url)
    entropy = -sum(
        (c / n) * math.log2(c / n)
        for c in counts.values()
    )

    if entropy > 4.5: score += 15
    elif entropy > 4.0: score += 8

    return score


def homograph_score(url):

    ext = tldextract.extract(url)

    domain = f"{ext.domain}.{ext.suffix}"

    if domain in SAFE_DOMAINS:
        return 0

    # separate domain label and suffix
    label = ext.domain
    suffix = ext.suffix

    # apply homograph substitutions
    normalized_label = "".join(HOMOGRAPH_MAP.get(c, c) for c in label)
    normalized_suffix = "".join(HOMOGRAPH_MAP.get(c, c) for c in suffix)

    normalized = unicodedata.normalize(
        "NFKC",
        f"{normalized_label}.{normalized_suffix}"
    )

    for safe in SAFE_DOMAINS:
        safe_name = safe.split(".")[0]

        if normalized.split(".")[0] == safe_name and normalized != safe:
            return 20

    return 0


def ip_score(url):

    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):
        return 20
    return 0


def subdomain_score(url):

    ext = tldextract.extract(url)

    if not ext.subdomain:
        return 0

    subdomains = ext.subdomain.split(".")

    if len(subdomains) >= 2:
        return 10

    return 0


def shortener_score(url):

    if extract_domain(url) in SHORTENERS:
        return 12
    return 0


def vt_score(malicious):

    malicious = max(0, int(malicious))

    if malicious == 0: return 0
    elif malicious <= 2: return 10
    elif malicious <= 5: return 20
    elif malicious <= 10: return 30
    else: return 40


def ml_score(confidence):

    confidence = max(0.0, min(confidence, 1.0))

    if confidence >= 0.85: return 30
    elif confidence >= 0.65: return 20
    elif confidence >= 0.45: return 10
    return 0


# ═══════════════════════════════════════════════════════════════
# RISK CLASSIFICATION
# ═══════════════════════════════════════════════════════════════

def classify_score(score):

    if score >= 75:
        return "high"
    elif score >= 25:
        return "medium"
    else:
        return "low"

# ═══════════════════════════════════════════════════════════════
# MAIN ANALYZER
# ═══════════════════════════════════════════════════════════════

def analyze_url_security(url, vt_malicious=0, ml_confidence=0.0):

    url = url.strip()

    if is_safe_domain(url):
        return {
            "risk":"low",
            "score":0,
            "reason":"Trusted domain whitelist"
        }

    raw = 0
    flags = []

    signals = [
        (ssl_score(url),"No HTTPS"),
        (keyword_score(url),"Phishing keywords"),
        (url_entropy_score(url),"High entropy URL"),
        (tld_score(url),"Suspicious TLD"),
        (homograph_score(url),"Homograph attack"),
        (ip_score(url),"IP address used"),
        (subdomain_score(url),"Too many subdomains"),
        (shortener_score(url),"URL shortener"),
        (ml_score(ml_confidence),f"ML confidence {round(ml_confidence*100)}%"),
        (vt_score(vt_malicious),f"VirusTotal {vt_malicious} engines")
    ]

    for score,reason in signals:
        if score:
            raw += score
            flags.append(reason)

    normalized = round((raw / MAX_SCORE) * 100)
    normalized = max(0, min(normalized, 100))

    return {
    "risk": classify_score(normalized),
    "score": normalized,
    "flags": flags,
    "reason": " | ".join(flags) if flags else "No threats detected"
}