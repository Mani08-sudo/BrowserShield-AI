import os
import re
from  backend.analysis.virustotal import check_file_hash as vt_check_hash

# ─────────────────────────────────────────────
#  FILE CLASSIFICATION CONFIG
# ─────────────────────────────────────────────

HIGH_RISK_EXTENSIONS = {
    ".exe":  "Windows executable",
    ".bat":  "Windows batch script",
    ".cmd":  "Windows command script",
    ".vbs":  "Visual Basic script",
    ".ps1":  "PowerShell script",
    ".msi":  "Windows installer package",
    ".dll":  "Dynamic link library",
    ".scr":  "Windows screensaver (often malware)",
    ".hta":  "HTML application (executes code)",
    ".pif":  "Program information file",
    ".jar":  "Java executable archive",
    ".sh":   "Shell script",
    ".bash": "Bash script",
    ".com":  "DOS executable",
}

MEDIUM_RISK_EXTENSIONS = {
    ".js":   "JavaScript file (can execute code)",
    ".vbe":  "Encoded VBScript",
    ".wsf":  "Windows script file",
    ".reg":  "Registry modification file",
    ".lnk":  "Windows shortcut (can point to malware)",
    ".iso":  "Disk image (can contain executables)",
    ".zip":  "Archive (may contain malicious files)",
    ".rar":  "Archive (may contain malicious files)",
    ".7z":   "Archive (may contain malicious files)",
    ".doc":  "Word document (may contain macros)",
    ".docm": "Word document with macros enabled",
    ".xlsm": "Excel file with macros enabled",
    ".pptm": "PowerPoint file with macros enabled",
    ".pdf":  "PDF (can contain malicious JavaScript)",
}

LOW_RISK_EXTENSIONS = {
    ".jpg": "JPEG image",
    ".jpeg":"JPEG image",
    ".png": "PNG image",
    ".gif": "GIF image",
    ".bmp": "Bitmap image",
    ".svg": "SVG image",
    ".mp4": "MP4 video",
    ".avi": "AVI video",
    ".mkv": "MKV video",
    ".mp3": "MP3 audio",
    ".wav": "WAV audio",
    ".txt": "Plain text file",
    ".csv": "CSV data file",
}

# Magic bytes (file signatures) for executables
# Used to detect disguised executables regardless of extension
MAGIC_BYTES = {
    b"MZ":         "Windows PE Executable (MZ header)",
    b"\x7fELF":    "Linux ELF Executable",
    b"PK\x03\x04": "ZIP Archive / Office Document",
    b"\xca\xfe\xba\xbe": "Java Class File",
    b"#!/":        "Unix Script (shebang)",
}

# Suspicious strings found inside file content
SUSPICIOUS_STRINGS = [
    b"powershell",
    b"cmd.exe",
    b"regsvr32",
    b"WScript",
    b"CreateObject",
    b"Shell.Application",
    b"HKEY_LOCAL_MACHINE",
    b"base64_decode",
    b"eval(",
    b"exec(",
    b"<script",
    b"document.write",
]
# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _check_magic_bytes(file_path):
    try:
        with open(file_path,"rb") as f:
            header=f.read(8)
        for magic,desc in MAGIC_BYTES.items():
            if header.startswith(magic):
                return desc
    except:
        pass
    return None


def _scan_content(file_path):
    found=[]
    try:
        with open(file_path,"rb") as f:
            content=f.read(50000).lower()
        for p in SUSPICIOUS_STRINGS:
            if p in content:
                found.append(p.decode(errors="ignore"))
    except:
        pass
    return found


def _check_double_extension(file_name):
    parts=file_name.lower().split(".")
    if len(parts)>=3:
        real="."+parts[-1]
        decoy="."+parts[-2]
        if real in HIGH_RISK_EXTENSIONS and decoy in LOW_RISK_EXTENSIONS:
            return True,f"Double extension: looks {decoy} but is {real}"
    return False,""


# ─────────────────────────────────────────────
# MAIN ANALYSIS
# ─────────────────────────────────────────────

def analyze_file(file_name,file_path=None):

    if not file_name:
        return "low","No file provided",{}

    ext=os.path.splitext(file_name)[1].lower()
    flags=[]
    score=0
    file_size=None

    # Extension checks
    double,reason=_check_double_extension(file_name)
    if double:
        score+=5; flags.append(reason)

    if ext in HIGH_RISK_EXTENSIONS:
        score+=4; flags.append(f"Executable type: {HIGH_RISK_EXTENSIONS[ext]}")
    elif ext in MEDIUM_RISK_EXTENSIONS:
        score+=2; flags.append(f"Risky type: {MEDIUM_RISK_EXTENSIONS[ext]}")
    elif ext not in LOW_RISK_EXTENSIONS:
        score+=1; flags.append("Unknown extension")

    # Deep inspection
    if file_path and os.path.exists(file_path):

        file_size=os.path.getsize(file_path)

        detected=_check_magic_bytes(file_path)
        if detected and ext not in HIGH_RISK_EXTENSIONS:
            score+=5; flags.append(f"Disguised executable: {detected}")

        suspicious=_scan_content(file_path)
        if suspicious:
            score+=min(len(suspicious),3)
            flags.append("Suspicious code patterns")

    # Rule decision
    if score>=5: risk="high"
    elif score>=2: risk="medium"
    else: risk="low"

    reason=flags[0] if flags else "Safe file"

    details={
        "extension":ext,
        "score":score,
        "flags":flags,
        "file_size":file_size,
        "virustotal":None
    }

    # ─────────────────────────────────────────────
    # SMART VIRUSTOTAL CHECK
    # ─────────────────────────────────────────────

    should_query_vt=False

    if file_path and os.path.exists(file_path):

        if risk=="high":
            should_query_vt=True
        elif ext in HIGH_RISK_EXTENSIONS and score>=3:
            should_query_vt=True
        elif any("disguised" in f.lower() for f in flags):
            should_query_vt=True

    if should_query_vt:

        vt=vt_check_hash(file_path)

        if vt:
            details["virustotal"]=vt
            order={"low":0,"medium":1,"high":2}

            if order[vt["risk"]]>order[risk]:
                risk=vt["risk"]
                reason=f"VirusTotal: {vt.get('verdict','malicious file')}"
                flags.append(f"{vt['malicious']} engines detected malware")
        else:
            details["virustotal"]={"status":"not configured"}

    else:
        details["virustotal"]={"status":"skipped — safe file"}

    return risk,reason,details