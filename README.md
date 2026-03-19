# 🛡️ BrowserShield
### AI-Driven Browser Security and Digital Forensics Platform

> A real-time browser-level security system that analyzes URLs, emails, and file downloads **before** the user interacts with them — combining rule-based detection, machine learning, and digital forensics logging.

---

## 📌 What is BrowserShield?

Most security tools react **after** a threat has been encountered. BrowserShield works differently — it acts as a security guard between the user and the internet, analyzing every action **before** it happens.

```
Normal browsing:
  User → Click link → Download file → Open email → THEN security reacts

BrowserShield:
  User tries action → System checks → Decision → Allow / Warn / Block
```

---

## 🎯 Key Features

| Feature | Description |
|---|---|
| 🔗 URL Analysis | 11-rule detection: IP addresses, suspicious TLDs, brand spoofing, homograph attacks |
| ✉️ Email Phishing Detection | Hybrid AI + rule-based analysis using TF-IDF + Logistic Regression |
| 📄 File Inspection | 30+ file extensions, magic byte detection, double-extension spoofing |
| 🔬 Static Sandbox | 7-step static analysis: hash check, entropy, pattern scanning, PE analysis |
| 📊 Forensics Dashboard | Real-time incident log with filters, stats, and auto-refresh |
| 🧩 Browser Extension | Chrome extension monitoring URLs, downloads, and webmail in real time |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Browser Extension                     │
│  background.js → monitors URLs, downloads               │
│  content.js    → scans Gmail / Outlook emails           │
│  popup.html    → shows live status and last scan        │
└────────────────────┬────────────────────────────────────┘
                     │ HTTP POST (JSON)
                     ▼
┌─────────────────────────────────────────────────────────┐
│                  Flask Backend (app.py)                  │
│                                                         │
│  /api/analyze-url    → url_analysis.py                  │
│  /api/analyze-email  → email_analysis.py + ML model     │
│  /api/analyze-file   → file_analysis.py + sandbox.py    │
│  /api/incidents      → forensics database queries       │
└────────────┬──────────────────────┬────────────────────┘
             │                      │
             ▼                      ▼
┌────────────────────┐   ┌─────────────────────────┐
│   ML Model         │   │   SQLite Database        │
│  email_model.pkl   │   │   incidents.db           │
│  vectorizer.pkl    │   │   (forensic evidence)    │
└────────────────────┘   └─────────────────────────┘
```

---

## 📁 Project Structure

```
BROWSER-SHIELD/
├── backend/
│   ├── app.py                    ← Flask entry point
│   ├── routes/                   ← API endpoints
│   │   ├── url_routes.py
│   │   ├── file_routes.py
│   │   ├── email_routes.py
│   │   └── incident_routes.py
│   ├── analysis/                 ← Detection logic
│   │   ├── url_analysis.py
│   │   ├── file_analysis.py
│   │   ├── email_analysis.py
│   │   ├── sandbox.py
│   │   └── ml_email_model.py
│   ├── database/
│   │   ├── db.py
│   │   └── incidents.db
│   └── templates/
│       └── dashboard.html
├── extension/                    ← Chrome Extension
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── popup.html
│   ├── popup.js
│   └── icons/
├── models/                       ← Trained ML models
│   ├── email_model.pkl
│   └── vectorizer.pkl
├── ml_training/                  ← Model training
│   ├── train_email_model.py
│   └── dataset/
│       └── SpamAssasin.csv
├── website/                      ← Public project website
├── docs/                         ← Architecture diagrams
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.8 or higher
- Google Chrome browser
- pip

### Step 1 — Clone the repository
```bash
git clone https://github.com/yourusername/browsershield.git
cd browsershield
```

### Step 2 — Create virtual environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Mac / Linux
source venv/bin/activate
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Train the ML model
```bash
cd ml_training
python train_email_model.py
cd ..
```
This generates `models/email_model.pkl` and `models/vectorizer.pkl`.

### Step 5 — Start the backend server
```bash
cd backend
python app.py
```
Server runs at: `http://127.0.0.1:5000`
Dashboard at: `http://127.0.0.1:5000/dashboard`

### Step 6 — Install the Chrome extension
1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer Mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `extension/` folder
5. The BrowserShield icon appears in your toolbar ✓

---

## 🔌 API Reference

### Analyze a URL
```http
POST /api/analyze-url
Content-Type: application/json

{ "url": "http://suspicious-login.xyz/verify" }
```
```json
{
  "url": "http://suspicious-login.xyz/verify",
  "risk": "high",
  "reason": "Suspicious TLD: .xyz (+2 more indicators)",
  "details": { "score": 7, "flags": [...] }
}
```

### Analyze an Email
```http
POST /api/analyze-email
Content-Type: application/json

{
  "subject": "Urgent: Verify your account now",
  "sender": "security@paypa1.com",
  "body": "Click here to verify..."
}
```
```json
{
  "risk": "high",
  "reason": "ML score: 0.94 | Phishing keywords: urgent, verify",
  "details": { "ml_score": 0.94, "rule_score": 6, "flags": [...] }
}
```

### Analyze a File
```http
POST /api/analyze-file
Content-Type: application/json

{ "file_name": "invoice.pdf.exe" }
```
```json
{
  "file_name": "invoice.pdf.exe",
  "risk": "high",
  "reason": "Double extension trick detected",
  "details": { "score": 5, "flags": [...] }
}
```

### Get All Incidents
```http
GET /api/incidents?risk=high&type=URL&limit=50&page=1
```

### Get Dashboard Stats
```http
GET /api/incidents/stats
```
```json
{
  "total": 142,
  "last_24h": 18,
  "by_risk": { "high": 34, "medium": 67, "low": 41 },
  "by_type": { "URL": 89, "EMAIL": 31, "FILE": 22 }
}
```

---

## 🧠 Machine Learning Model

- **Dataset**: SpamAssassin (public phishing/ham email dataset)
- **Algorithm**: Logistic Regression (selected after comparing with Random Forest and Linear SVM)
- **Features**: TF-IDF with unigrams + bigrams, 8,000 features
- **Approach**: Hybrid — ML probability score combined with rule-based scoring

| Metric | Score |
|---|---|
| Accuracy | — (run `train_email_model.py` to generate) |
| F1 Score | — |
| ROC-AUC | — |
| False Positive Rate | — |

> Run `ml_training/train_email_model.py` to train the model and generate the full evaluation report at `models/evaluation_report.txt`.

---

## 🔍 Detection Capabilities

### URL Analysis (11 rules)
- IP address used instead of domain name
- No HTTPS encryption
- Suspicious TLDs (`.xyz`, `.tk`, `.ml`, `.cf`)
- Brand name spoofing in domain
- Excessive subdomains
- Suspicious keywords (`login`, `verify`, `secure`, `bank`)
- Homograph / encoded characters
- Domain length anomaly
- Excessive hyphens
- URL length anomaly
- Trusted domain whitelist

### Email Analysis
- 30+ phishing keyword patterns
- ML probability scoring (0.0 – 1.0)
- Sender domain mismatch detection
- Display name spoofing
- HTML anchor text vs href mismatch
- Hidden text detection
- Urgency pattern matching
- Multi-URL and multi-domain detection

### File Analysis
- 14 high-risk extensions (`.exe`, `.ps1`, `.bat`, `.vbs`, `.hta` ...)
- 13 medium-risk extensions (`.docm`, `.pdf`, `.iso`, `.zip` ...)
- Double extension trick detection (`invoice.pdf.exe`)
- Magic byte / file header verification
- Static sandbox: entropy analysis, pattern scanning, PE header analysis

---

## 🔬 Sandbox Analysis

The sandbox performs **static analysis** (file is never executed):

1. **Hash check** — MD5 against known malware database
2. **Magic byte detection** — verifies real file type vs extension
3. **Entropy analysis** — high entropy (>7.0) indicates encryption/packing
4. **Pattern scanning** — 35 suspicious code patterns
5. **PE header analysis** — checks Windows executable imports
6. **Extension spoofing detection** — catches disguised executables
7. **File size anomaly** — flags suspiciously tiny executables

---
────────────────────────────────────────────────────────────
  TRAINING COMPLETE
────────────────────────────────────────────────────────────
  Best Model:    Linear SVM
  Accuracy:      98.88%
  F1 Score:      0.9812
  ROC-AUC:       0.9979
  FP Rate:       0.98% (safe emails wrongly flagged)
  FN Rate:       1.45% (phishing emails missed)

## 🛠️ Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask |
| ML / AI | scikit-learn, TF-IDF, Logistic Regression |
| Database | SQLite |
| Browser Extension | JavaScript (Chrome Manifest V3) |
| Frontend | HTML, CSS, JavaScript |
| Data | SpamAssassin dataset |

---

## 🚀 Future Improvements

- [ ] VirusTotal API integration for real-time hash lookup
- [ ] Dynamic sandbox using isolated VM execution
- [ ] BERT/transformer-based email classification
- [ ] Real-time dashboard WebSocket updates
- [ ] Firefox extension support
- [ ] User behavior analytics
- [ ] Threat intelligence feed integration

---

## 👨‍💻 Author

**Manisha Banshiwal**
Mini Project — NFSU
MSC DFIS
2026

---

## 📄 License

This project is developed for academic purposes as part of a mini project submission.

---

*BrowserShield — Protecting users before they interact, not after.*

