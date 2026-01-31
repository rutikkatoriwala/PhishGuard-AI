# 🛡️ PhishGuard AI: Predictive Threat Intelligence Platform

PhishGuard AI is a professional-grade cybersecurity platform designed to intercept phishing and system compromise threats using Machine Learning and Static Heuristic Analysis. Unlike traditional rule-based filters, PhishGuard AI predicts malicious intent by analyzing the structural DNA of URLs and documents.

![PhishGuard AI Banner](static/emerald_security_hero_new_1769231170915.png)

## 🚀 Key Features

### 1. ML-Driven URL Analysis
*   **Massive Dataset:** Powered by a model trained on over **651,000+ biological URL samples**.
*   **Predictive Engine:** Uses a **Random Forest Classifier** to evaluate 13+ structural features (length, subdomain entropy, suspicious character density, etc.).
*   **Model Confidence:** Provides a statistical probability score for every detection.

### 2. Dual-Vector File Scanner
*   **Static Artifact Inspection:** Scans `.pdf` and `.txt` files for hidden malicious code without executing them.
*   **Theorem Recognition:** Hunts for TTPs (Tactics, Techniques, and Procedures) used by attackers:
    *   **Reverse Shells:** Detects `nc -e`, `sh -i`, and socket manipulation.
    *   **Persistence:** Identifies attempts to modify Windows Registry/Startup folders.
    *   **Data Exfiltration:** Flags suspicious `POST` requests and `curl` commands.
    *   **PDF Exploits:** Detects unauthorized `/OpenAction` and `/JavaScript` triggers.

### 3. Professional SOC Reporting
*   **Incident Tickets:** Generates a structured **Security Operations Center (SOC)** report for every detection.
*   **Unique Traceability:** Each threat is assigned a unique `Incident ID`.
*   **Mitigation Plan:** Provides actionable "Next Steps" for security analysts to neutralize the threat.

---

## 🛠️ Technology Stack

*   **Backend:** Python (Flask)
*   **Machine Learning:** Scikit-Learn, Pandas, NumPy, Joblib
*   **Security Analysis:** Regex-based Heuristics, PyPDF2
*   **Frontend:** HTML5, CSS3 (Modern Glassmorphism Design), Vanilla JavaScript

---

## 📦 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/rutikkatoriwala/PhishGuard-AI.git
cd PhishGuard-AI
```

### 2. Install Dependencies
```bash
pip install flask flask-cors joblib scikit-learn PyPDF2 pandas numpy
```

### 3. Initialize the AI Model
If the `.pkl` models are not included in the repository (due to size limits), train the model locally:
```bash
python train_model.py
```

### 4. Run the Application
```bash
python app.py
```
Visit `http://127.0.0.1:5000` in your browser.

---

## 🧠 Model Architecture & Methodology

The core of PhishGuard AI is its **Weighted Risk-Scoring Engine**:

| Component | Weight | Description |
| :--- | :--- | :--- |
| **THREAT_SIGNATURE** | 35 | High-level triggers (Shell hooks, Persistence) |
| **MALICIOUS_LINK** | 25 | URL identified as malicious by the ML model |
| **SUSPICIOUS_PATTERN** | 15 | Obfuscation techniques (Base64, eval, exec) |

**Thresholds:**
*   **Risk ≥ 60:** 🚫 CRITICAL THREAT Detected
*   **Risk ≥ 20:** ⚠️ SUSPICIOUS Activity Flagged
*   **Risk < 20:** ✅ CLEAN Artifact

---

## ⚠️ Technical Caveats
*   **Static Analysis:** This tool performs static inspection. It does not run files in a sandbox (Dynamic Analysis).
*   **Git Compliance:** The `phishing_model.pkl` (228MB) is excluded from this repository via `.gitignore` to comply with GitHub size limits. You must train it locally or download it from the provided release link.

---

## 📄 License & Credits
Developed by **Rutik Katoriwala**.
Inspired by modern SOC workflows and AI-assisted threat hunting.
