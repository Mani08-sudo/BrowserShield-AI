"""
sandbox.py — Static Sandbox Analysis Module
============================================
Performs static analysis on files to detect malicious behavior
WITHOUT executing them. This is safe sandboxing — the file is
never run, only inspected.

Real dynamic sandboxing (actually running the file in an isolated VM)
would require tools like Cuckoo Sandbox. This module provides a
practical static alternative suitable for a browser security system.
"""

import os
import re
import math
import hashlib
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
#  KNOWN MALICIOUS FILE HASHES (MD5)
#  In production: pull from threat intel feeds
#  like VirusTotal, MalwareBazaar, etc.
# ─────────────────────────────────────────────

KNOWN_MALICIOUS_HASHES = {
    # Format: "md5_hash": "malware_name"
    # Add real hashes here from threat intelligence feeds
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test File",
    "e44a2b8b7c2a4a5e3d8b7c2a4a5e3d8b": "Example.Trojan",
}

# ─────────────────────────────────────────────
#  SUSPICIOUS PATTERNS IN FILE CONTENT
# ─────────────────────────────────────────────

# Each entry: (pattern_bytes, description, severity_score)
SUSPICIOUS_PATTERNS = [
    # Remote access / C2 communication
    (b"socket.connect",          "Network socket connection attempt",      3),
    (b"urllib.request",          "HTTP request in executable",             2),
    (b"requests.get",            "HTTP GET request in executable",         2),
    (b"wget ",                   "wget download command",                  3),
    (b"curl ",                   "curl download command",                  3),

    # System manipulation
    (b"cmd.exe",                 "CMD shell execution",                    3),
    (b"powershell",              "PowerShell execution",                   3),
    (b"regsvr32",                "DLL registration abuse",                 3),
    (b"schtasks",                "Scheduled task creation",                2),
    (b"net user",                "User account manipulation",              3),
    (b"net localgroup",          "Group membership manipulation",          3),
    (b"icacls",                  "File permission modification",           2),
    (b"attrib +h",               "File hidden attribute set",              2),

    # Registry manipulation
    (b"HKEY_LOCAL_MACHINE",      "Registry access (HKLM)",                 2),
    (b"HKEY_CURRENT_USER",       "Registry access (HKCU)",                 1),
    (b"reg add",                 "Registry key addition",                  3),
    (b"reg delete",              "Registry key deletion",                  3),

    # Code execution tricks
    (b"WScript.Shell",           "Windows Script Host shell access",       3),
    (b"Shell.Application",       "Shell application COM object",           3),
    (b"CreateObject",            "COM object creation",                    2),
    (b"eval(",                   "Dynamic code evaluation",                2),
    (b"exec(",                   "Dynamic code execution",                 2),
    (b"base64_decode",           "Base64 decoding (obfuscation)",          2),
    (b"fromCharCode",            "Character code obfuscation",             2),

    # Anti-analysis tricks
    (b"IsDebuggerPresent",       "Debugger detection attempt",             3),
    (b"VirtualAllocEx",          "Remote memory allocation (injection)",   4),
    (b"WriteProcessMemory",      "Process memory writing (injection)",     4),
    (b"CreateRemoteThread",      "Remote thread creation (injection)",     4),

    # Persistence mechanisms
    (b"Startup",                 "Startup folder reference",               2),
    (b"autorun",                 "Autorun reference",                      2),

    # Data exfiltration
    (b"ftp://",                  "FTP connection (data exfiltration risk)", 2),
    (b"smtp",                    "SMTP email sending",                     2),
    (b"keylog",                  "Keylogger reference",                    4),
    (b"screenshot",              "Screenshot capture",                     2),

    # Script injection
    (b"<script>",                "Embedded script tag",                    2),
    (b"document.write",          "DOM manipulation",                       1),
    (b"iframe",                  "Embedded iframe",                        1),
]

# ─────────────────────────────────────────────
#  MAGIC BYTES (File Header Signatures)
# ─────────────────────────────────────────────

MAGIC_SIGNATURES = {
    b"MZ":              ("Windows PE Executable",   "high"),
    b"\x7fELF":         ("Linux ELF Executable",    "high"),
    b"\xca\xfe\xba\xbe":("Java Class File",         "medium"),
    b"PK\x03\x04":      ("ZIP/Office Archive",      "low"),
    b"%PDF":            ("PDF Document",            "low"),
    b"#!/":             ("Unix Shell Script",       "medium"),
    b"#!":              ("Script File",             "medium"),
}


def _compute_hash(file_path):
    """Computes MD5 hash of file for threat intel lookup."""
    try:
        md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
        return md5.hexdigest()
    except Exception as e:
        logger.warning(f"Hash computation failed: {e}")
        return None


def _compute_entropy(data):
    """
    Computes Shannon entropy of byte data.
    High entropy (>7.0) suggests encryption or packing — common in malware.
    Normal files: 4.0–6.5. Encrypted/packed: 7.0–8.0.
    """
    if not data:
        return 0.0

    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    entropy = 0.0
    length  = len(data)
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return round(entropy, 3)


def _detect_magic_bytes(file_path):
    """Reads file header to determine real file type."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
        for magic, (description, risk) in MAGIC_SIGNATURES.items():
            if header.startswith(magic):
                return description, risk
    except Exception:
        pass
    return "Unknown", "low"


def _scan_patterns(file_path, max_bytes=100000):
    """
    Scans file content for suspicious code patterns.
    Returns list of (description, score) tuples.
    """
    findings = []
    try:
        with open(file_path, "rb") as f:
            content = f.read(max_bytes).lower()

        for pattern, description, score in SUSPICIOUS_PATTERNS:
            if pattern.lower() in content:
                findings.append((description, score))

    except Exception as e:
        logger.warning(f"Pattern scan failed: {e}")

    return findings


def _check_pe_structure(file_path):
    """
    Basic PE (Windows Executable) header analysis.
    Checks for suspicious PE characteristics.
    """
    findings = []
    try:
        with open(file_path, "rb") as f:
            header = f.read(512)

        # Check for MZ header (Windows executable)
        if header[:2] == b"MZ":
            # Look for suspicious imports in header strings
            header_str = header.lower()
            if b"urldownloadtofile" in header_str:
                findings.append(("Downloads files from internet (URLDownloadToFile)", 4))
            if b"internetopenurl" in header_str:
                findings.append(("Opens internet connections", 3))
            if b"createprocess" in header_str:
                findings.append(("Spawns new processes", 2))

    except Exception:
        pass

    return findings


def run_sandbox(file_path, file_name=None):
    """
    Main sandbox analysis function.
    Performs static analysis without executing the file.

    Args:
        file_path: Absolute path to the file to analyze
        file_name: Original filename (optional, for display)

    Returns:
        dict with keys:
            - verdict:     "safe" | "suspicious" | "malicious"
            - risk:        "low"  | "medium"     | "high"
            - score:       int (cumulative threat score)
            - findings:    list of detected issues
            - file_hash:   MD5 hash of file
            - entropy:     Shannon entropy score
            - file_type:   Detected file type
            - timestamp:   Analysis timestamp
            - summary:     Human-readable verdict string
    """
    result = {
        "verdict":   "safe",
        "risk":      "low",
        "score":     0,
        "findings":  [],
        "file_hash": None,
        "entropy":   None,
        "file_type": "Unknown",
        "timestamp": datetime.utcnow().isoformat(),
        "summary":   "No threats detected"
    }

    # ── Validate file exists ──────────────────────────────────────────
    if not file_path or not os.path.exists(file_path):
        result["summary"] = "File not found for analysis"
        result["risk"]    = "medium"
        result["verdict"] = "suspicious"
        return result

    file_name = file_name or os.path.basename(file_path)
    score     = 0
    findings  = []

    try:
        # ── Step 1: Compute file hash ─────────────────────────────────
        file_hash = _compute_hash(file_path)
        result["file_hash"] = file_hash

        # ── Step 2: Check against known malicious hashes ──────────────
        if file_hash and file_hash in KNOWN_MALICIOUS_HASHES:
            malware_name = KNOWN_MALICIOUS_HASHES[file_hash]
            score  += 10   # Definitive match
            findings.append(f"KNOWN MALWARE: {malware_name} (hash match)")

        # ── Step 3: Detect real file type via magic bytes ─────────────
        file_type, type_risk = _detect_magic_bytes(file_path)
        result["file_type"] = file_type

        # Check for extension spoofing
        ext = os.path.splitext(file_name)[1].lower()
        if "Executable" in file_type and ext not in [".exe", ".dll", ".com", ".scr"]:
            score  += 5
            findings.append(
                f"Extension spoofing: file has '{ext}' extension but is actually {file_type}"
            )

        # ── Step 4: Entropy analysis ──────────────────────────────────
        with open(file_path, "rb") as f:
            sample = f.read(50000)

        entropy = _compute_entropy(sample)
        result["entropy"] = entropy

        if entropy > 7.5:
            score  += 3
            findings.append(
                f"Very high entropy ({entropy}) — file may be encrypted or packed (malware evasion)"
            )
        elif entropy > 7.0:
            score  += 1
            findings.append(f"High entropy ({entropy}) — possible packing or encryption")

        # ── Step 5: Suspicious pattern scanning ───────────────────────
        pattern_findings = _scan_patterns(file_path)
        for description, pscore in pattern_findings:
            score    += pscore
            findings.append(f"Suspicious pattern: {description}")

        # ── Step 6: PE header analysis (for .exe files) ───────────────
        pe_findings = _check_pe_structure(file_path)
        for description, pscore in pe_findings:
            score    += pscore
            findings.append(f"PE analysis: {description}")

        # ── Step 7: File size anomalies ───────────────────────────────
        file_size = os.path.getsize(file_path)
        ext_lower = os.path.splitext(file_name)[1].lower()
        if ext_lower == ".exe" and file_size < 1024:
            score  += 2
            findings.append(f"Suspiciously small executable ({file_size} bytes)")
        elif file_size == 0:
            score  += 1
            findings.append("File is empty (0 bytes)")

    except Exception as e:
        logger.error(f"Sandbox analysis error: {e}")
        findings.append(f"Analysis error: {str(e)}")

    # ── Final verdict ─────────────────────────────────────────────────
    result["score"]    = score
    result["findings"] = findings

    if score >= 8:
        result["verdict"] = "malicious"
        result["risk"]    = "high"
        result["summary"] = f"MALICIOUS — {len(findings)} threat indicators detected (score: {score})"

    elif score >= 3:
        result["verdict"] = "suspicious"
        result["risk"]    = "medium"
        result["summary"] = f"SUSPICIOUS — {len(findings)} indicators found (score: {score})"

    else:
        result["verdict"] = "safe"
        result["risk"]    = "low"
        result["summary"] = "No significant threats detected"

    return result