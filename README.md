# 🛡️ BrowserShield

## AI-Driven Browser Security & Digital Forensics Platform

> A real-time browser-level security system that analyzes URLs, emails, and file downloads **before user interaction** using heuristic rules, machine learning, and threat intelligence — with built-in digital forensics logging.

---

# 📌 What is BrowserShield?

Traditional security tools react **after a threat occurs**. BrowserShield takes a **proactive approach**:

```text
Normal Flow:
User → Click → Threat executes → Detection

BrowserShield Flow:
User Action → Pre-analysis → Decision → Allow / Warn / Block
```

It acts as a **security layer between the user and the internet**.

---

# 🎯 Key Features

| Feature                     | Description                                                        |
| --------------------------- | ------------------------------------------------------------------ |
| 🔗 URL Analysis             | Rule-based + ML detection (TLD, entropy, keywords, spoofing, etc.) |
| ✉️ Email Phishing Detection | TF-IDF + Logistic Regression + rule-based scoring                  |
| 📄 File Inspection          | Extension checks, double-extension detection                       |
| 🔬 Static Sandbox           | Entropy + pattern + PE-based static analysis                       |
| 📊 Forensics Dashboard      | Real-time logs, statistics, monitoring                             |
| 🧩 Chrome Extension         | Monitors URLs, downloads, and email content                        |

---

# 🏗️ System Architecture

```text
User Browser
     ↓
BrowserShield Extension
     ↓
Flask API Layer
     ↓
Threat Detection Engine
 ├ Heuristic Rules
 ├ Machine Learning Model
 ├ File Analysis + Sandbox
 └ Threat Intelligence (VirusTotal)
     ↓
Threat Score Calculation
     ↓
SQLite Database (Forensics)
     ↓
Dashboard UI
```

---

# 🔍 Core Detection Engine

### 🔹 Heuristic Analysis

* URL structure checks
* Suspicious keywords
* Domain and TLD analysis
* Entropy & anomaly detection

---

### 🔹 Machine Learning

* TF-IDF vectorization
* Logistic Regression (Email detection)
* Random Forest (URL model)
* Outputs probability score

---

### 🔹 Threat Intelligence

* VirusTotal API integration (optional)
* Multi-engine reputation check

---

### 🔹 File & Sandbox Analysis

* Extension-based detection
* Static analysis (entropy, patterns)
* No execution → safe sandbox

---

# 📊 Threat Scoring System

The system uses a **weighted scoring model**:

```text
Final Score =
Heuristic Score
+ ML Score
+ Threat Intelligence Score
```

### Risk Levels

| Score | Risk   |
| ----- | ------ |
| 0–39  | Low    |
| 40–79 | Medium |
| 80+   | High   |

---

# 🧾 Digital Forensics

BrowserShield logs all detected threats:

* URL / Email / File
* Threat score
* Risk level
* Detection reasons
* Timestamp
* Action taken

👉 Enables **incident investigation and analysis**

---

# 📁 Project Structure

BrowserShield-AI/
├── backend/                         ← Core backend system (Flask)
│   ├── app.py                       ← Main server entry point
│   │
│   ├── routes/                      ← API endpoints (request handling)
│   │   ├── url_routes.py
│   │   ├── email_routes.py
│   │   ├── file_routes.py
│   │   ├── incident_routes.py
│   │   └── predict_url.py
│   │
│   ├── analysis/                    ← Detection & analysis logic
│   │   ├── url_analysis.py
│   │   ├── email_analysis.py
│   │   ├── file_analysis.py
│   │   ├── sandbox.py
│   │   ├── ml_email_model.py
│   │   └── virustotal.py
│   │
│   ├── security/                    ← Threat scoring & decision engine
│   │   └── threat_engine.py
│   │
│   ├── database/                    ← Data storage layer
│   │   ├── db.py
│   │   └── incidents.db
│   │
│   └── templates/                   ← Web dashboard UI
│       └── dashboard.html
│
├── extension/                       ← Chrome browser extension
│   ├── manifest.json
│   ├── background.js               ← Monitors URLs & downloads
│   ├── content.js                  ← Scans email content (Gmail/Outlook)
│   ├── popup.html                  ← User interface
│   ├── popup.js
│   ├── warning.html
│   ├── warning.js
│   └── icons/
│
├── models/                          ← Trained machine learning models
│   ├── email_model.pkl
│   ├── phishing_model.pkl
│   ├── vectorizer.pkl
│   └── evaluation_report.txt
│
├── ml_training/                     ← Model training scripts
│   ├── train_email_model.py
│   ├── train_url_model.py
│   └── dataset/                     ← Training datasets (optional)
│       └── SpamAssasin.csv
│
├── website/                         ← Public project website (UI pages)
│   ├── index.html
│   ├── about.html
│   ├── download.html
│   ├── flow.html
│   ├── css/
│   └── js/
│
├── docs/                            ← Architecture & flow diagrams
│   ├── architecture.png
│   └── flowchart.png
│
├── requirements.txt                 ← Python dependencies
├── .gitignore                       ← Ignored files (env, logs, db, etc.)
├── .env.example                     ← Sample environment variables
└── README.md                        ← Project documentation
---

# ⚙️ Installation & Setup

## Prerequisites

* Python 3.8+
* Google Chrome
* pip

---

## 1. Clone Repository

```bash
git clone https://github.com/Mani08-sudo/BrowserShield-AI.git
cd BrowserShield-AI
```

---

## 2. Create Virtual Environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / Mac
source venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Train Models

```bash
cd ml_training
python train_email_model.py
python train_url_model.py
cd ..
```

---

## 5. Run Backend

```bash
cd backend
python app.py
```

* API: [http://127.0.0.1:5000](http://127.0.0.1:5000)
* Dashboard: [http://127.0.0.1:5000/dashboard](http://127.0.0.1:5000/dashboard)

---

## 6. Load Chrome Extension

1. Open: `chrome://extensions/`
2. Enable **Developer Mode**
3. Click **Load unpacked**
4. Select `extension/` folder

---

# 🔌 API Endpoints

### URL Analysis

```http
POST /api/analyze-url
```

### Email Analysis

```http
POST /api/analyze-email
```

### File Analysis

```http
POST /api/analyze-file
```

### Get Incidents

```http
GET /api/incidents
```

---

# 🧠 Machine Learning

### Email Model

* Dataset: SpamAssassin
* Algorithm: Logistic Regression
* Features: TF-IDF

### URL Model

* Dataset: Balanced phishing URL dataset
* Algorithm: Random Forest

---

# 📈 Model Evaluation

## 📊 Model Performance

The machine learning model was trained using the SpamAssassin dataset and evaluated on a test set.

- **Accuracy:** 95.01%  
- **F1 Score:** 0.9485  
- **ROC-AUC:** 0.9870  
- **False Positive Rate:** 1.23%  

### Confusion Matrix

|                | Predicted Legit | Predicted Phishing |
|----------------|----------------|--------------------|
| **Actual Legit**   | 1122 (TN)      | 14 (FP)            |
| **Actual Phishing**| 100 (FN)       | 1050 (TP)          |

### Interpretation

- The model achieves **high accuracy and strong ROC-AUC**, indicating excellent classification performance.  
- The **low false positive rate (1.23%)** ensures minimal impact on legitimate emails.  
- The model effectively detects phishing emails with high precision and recall.
# 🔍 Detection Capabilities

## URL Detection

* Suspicious TLDs
* Phishing keywords
* IP-based URLs
* Homograph attacks
* Subdomain anomalies

---

## Email Detection

* Sender spoofing
* Keyword detection
* Link extraction
* ML probability scoring

---

## File Detection

* Double extensions
* Dangerous file types
* Static sandbox analysis

---

# 🔬 Sandbox Analysis

Performs **static analysis only**:

* Hash checking
* Entropy analysis
* Pattern scanning
* File header validation

---

# 🛠️ Tech Stack

| Layer     | Technology    |
| --------- | ------------- |
| Backend   | Python, Flask |
| ML        | Scikit-learn  |
| Database  | SQLite        |
| Extension | JavaScript    |
| Frontend  | HTML, CSS     |

---

# 🚀 Future Work

* Dynamic sandbox (VM-based)
* BERT-based phishing detection
* Real-time WebSocket dashboard
* DNS reputation system
* Firefox extension

---

# 👨‍💻 Author

**Manisha Banshiwal**
MSc DFIS — NFSU (2026)

---

# 📄 License

Academic Project — For educational use only

