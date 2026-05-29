# PhishGuard 🛡️

**ML-Powered Phishing URL Detection with Cyber Threat Intelligence**

PhishGuard detects phishing URLs in real time by combining a trained Machine Learning model with live threat intelligence — VirusTotal, URLHaus, WHOIS, DNS forensics, and typosquatting detection. It works as a Chrome extension that scans every visited URL and surfaces results through an analyst dashboard.

---

## Live Links

|               |                                           |
| ------------- | ----------------------------------------- |
| **Dashboard** | https://phish-guard-sooty.vercel.app      |
| **API Docs**  | https://phishguard-10mf.onrender.com/docs |
| **GitHub**    | https://github.com/Sanjana1912/PhishGuard |

---

## How It Works

```
You visit a URL
      ↓
Chrome Extension captures it
      ↓
FastAPI Backend runs 5 checks simultaneously:
  ├── ML Model        (Random Forest, 92.93% accuracy)
  ├── VirusTotal      (90+ security vendors)
  ├── URLHaus         (malicious URL blacklist)
  ├── WHOIS / DNS     (domain age + DNS forensics)
  └── Typosquatting   (Levenshtein distance vs top domains)
      ↓
Risk Engine combines all signals → score 0–100
      ↓
Result shown in extension popup + saved to dashboard
```

---

## Risk Engine

Custom weighted scoring — no hardcoded rules, no binary thresholds. Every point added has an explainable reason.

| Signal                                           | Max Points |
| ------------------------------------------------ | ---------- |
| ML Model probability                             | 35         |
| VirusTotal vendor ratio                          | 25         |
| Typosquatting (major brands boosted)             | 25         |
| Domain age via WHOIS                             | 20         |
| Brand name embedded in domain                    | 18         |
| Structural URL analysis (hyphens, length, depth) | 22         |
| URLHaus blacklist                                | 15         |
| Suspicious TLD                                   | 10         |
| DNS anomalies                                    | 10         |
| **Total (capped at 100)**                        | **100**    |

**Risk Levels:** 🟢 LOW (0–21) · 🟡 MEDIUM (22–44) · 🟠 HIGH (45–74) · 🔴 CRITICAL (75–100)

---

## ML Model

- **Dataset:** 651,191 URLs — benign, phishing, defacement, malware
- **Features:** 48 engineered URL features (length, entropy, brand similarity, TLD, subdomain depth, special chars, etc.)
- **Models trained:** Logistic Regression · Gradient Boosting · XGBoost · Random Forest
- **Selected:** Random Forest (best F1 + recall)

| Metric    | Score  |
| --------- | ------ |
| Accuracy  | 92.93% |
| Precision | 95.53% |
| Recall    | 83.25% |
| F1-Score  | 88.97% |
| ROC-AUC   | 97.09% |

---

## Tech Stack

| Layer        | Technology                                                     |
| ------------ | -------------------------------------------------------------- |
| ML           | Python, scikit-learn, RandomForest, XGBoost, joblib            |
| Backend      | Python, FastAPI, asyncio, Motor                                |
| Threat Intel | httpx, python-whois, dnspython, python-Levenshtein, tldextract |
| Database     | MongoDB Atlas                                                  |
| Frontend     | React, Vite, Tailwind CSS, Recharts                            |
| Extension    | JavaScript, Manifest V3                                        |
| Deployment   | Render (backend) · Vercel (frontend) · MongoDB Atlas (db)      |

---

## Project Structure

```
PhishGuard/
├── backend/
│   ├── app/
│   │   ├── core/
│   │   │   ├── risk_engine.py     ← 9-signal weighted scoring formula
│   │   │   └── config.py          ← environment variables
│   │   ├── ml/
│   │   │   ├── predictor.py       ← loads model, runs predict_proba()
│   │   │   └── phishing_detector_enhanced.pkl
│   │   ├── routers/               ← scan, history, report, auth
│   │   └── services/              ← virustotal, urlhaus, whois_dns, typosquatch, deobfuscator
│   ├── notebooks/
│   │   └── model_training.ipynb   ← 651K URLs, 4 models compared
│   ├── Dockerfile
│   └── requirements.txt
├── extension/
│   ├── popup/                     ← risk UI, API call, color-coded results
│   ├── background/service_worker.js  ← badge + desktop notifications
│   └── manifest.json              ← Manifest V3
├── frontend/
│   └── src/
│       ├── pages/                 ← Dashboard, Analytics, Reports, Auth
│       ├── components/            ← RiskBadge, ScanResultPanel, ReportsTable, Charts
│       └── services/api.js        ← axios client
└── README.md
```

---

## API

| Method | Endpoint           | Description                             |
| ------ | ------------------ | --------------------------------------- |
| POST   | `/api/scan`        | Scan a URL — returns full threat report |
| GET    | `/api/history`     | Recent scan history                     |
| GET    | `/api/report/{id}` | Full report by scan ID                  |

**Example:**

```bash
curl -X POST https://phishguard-10mf.onrender.com/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://secure-paypal-login.com"}'
```

**Sample response:**

```json
{
    "scan_id": "2d835627-2628-4865-bdae-ec...",
    "url": "http://secure-paypal-login.com",
    "risk_score": 87,
    "risk_level": "CRITICAL",
    "prediction": "phishing",
    "explanation": "ML model flagged as phishing (94% confidence). Flagged by 10 VirusTotal vendors. Brand name 'paypal' embedded in non-official domain. Domain has 2 hyphens.",
    "threat_intel": {
        "virustotal": { "malicious_count": 10, "total_vendors": 92 },
        "urlhaus": { "is_blacklisted": false },
        "typosquatting": { "is_typosquat": false },
        "ml": { "ml_score": 0.94, "ml_confidence": 94, "ml_ready": true }
    }
}
```

---

## Local Setup

```bash
# Clone
git clone https://github.com/Sanjana1912/PhishGuard.git
cd PhishGuard

# Backend
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
pip install -r requirements.txt
cp .env.example .env         # fill in your API keys
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev
```

**Required `.env` variables:**

```
VIRUSTOTAL_API_KEY=    # free at virustotal.com
URLHAUS_API_KEY=       # free at urlhaus.abuse.ch
MONGO_URI=             # MongoDB Atlas connection string
DB_NAME=phishguard
APP_ENV=development
```

**Chrome Extension:**

1. Open `chrome://extensions/`
2. Enable Developer mode
3. Load unpacked → select `extension/` folder
4. Pin PhishGuard to toolbar

---
