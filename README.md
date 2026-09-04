# SIH26106: AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform

[![Vercel](https://img.shields.io/badge/Vercel-Live_Deployment-black.svg?logo=vercel&logoColor=white)](https://frontend-lake-ten-eg3jz3wr5r.vercel.app)
[![GitHub](https://img.shields.io/badge/GitHub-Sreyash308%2Fsih26106--threat--platform-181717.svg?logo=github&logoColor=white)](https://github.com/Sreyash308/sih26106-threat-platform)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-14_App_Router-black.svg?logo=next.js&logoColor=white)](https://nextjs.org)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://python.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-3178C6.svg?logo=typescript&logoColor=white)](https://typescriptlang.org)
[![Leaflet](https://img.shields.io/badge/Leaflet-1.9.4-199900.svg?logo=leaflet&logoColor=white)](https://leafletjs.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Smart India Hackathon (SIH) Problem ID:** SIH26106  
> **Organization:** All India Council for Technical Education (AICTE)  
> **Category:** Cybersecurity / Digital Forensics / AI / Network Security  
> **🌐 Live Web Console:** [https://frontend-lake-ten-eg3jz3wr5r.vercel.app](https://frontend-lake-ten-eg3jz3wr5r.vercel.app)  
> **📦 GitHub Repository:** [https://github.com/Sreyash308/sih26106-threat-platform](https://github.com/Sreyash308/sih26106-threat-platform)

---

## 1. Executive Summary & Problem Statement

Modern enterprise environments face an onslaught of sophisticated email threats—from credential harvesting and Business Email Compromise (BEC) to executive impersonation and weaponized multi-stage attachments. Existing email security gateways often operate as opaque "black boxes," delivering binary verdicts without explaining **why** a message was flagged or tracing the **geographic network trajectory** traversed by the malicious payload.

**SIH26106 Platform** is a Security Operations Center (SOC) grade digital forensics and threat intelligence platform. It ingests raw `.eml` files or pasted RFC 2822 headers/bodies and executes a rigorous **20-stage forensic pipeline**:
1. Unpacks MIME structures and decodes RFC 2047 multi-charset headers.
2. Evaluates SPF, DKIM, and DMARC alignment to compute an independent **Header Trust Score (0–100)**.
3. Performs Sender anomaly detection (lookalike domains, punycode, display-name spoofing, Reply-To mismatches).
4. Forensically reconstructs the chronological relay hop order from reverse `Received:` headers.
5. Classifies all IP addresses (Public, Private, Loopback, Documentation) and maps geographic coordinates with interactive Leaflet flight polyline routes.
6. Extracts all URLs and detects obfuscations, anchor mismatches, and raw IP destinations without crawling (100% SSRF-safe).
7. Identifies cryptocurrency addresses (Bitcoin, Ethereum) embedded in extortion or ransomware lures.
8. Computes cryptographic hashes (SHA-256, SHA-1, MD5) for attachments and flags dangerous/double extensions (`.pdf.exe`).
9. Analyzes linguistic urgency and social-engineering intent via a dual-engine NLP system (TF-IDF classifier + rule-based heuristic scoring).
10. Calculates an explainable, factor-attributed **Threat Score (0–100)** and categorizes severity from **SAFE** to **CRITICAL**.
11. Generates publication-ready **PDF forensic reports** (via ReportLab) and machine-readable **JSON packages**.
12. Provides complete investigation case triage, persistent analyst notes, and live telemetry feeds.

---

## 2. Core Product Principles

### Honest Provenance & Threat Labeling
In accordance with strict digital forensics standards, this platform **never fabricates threat intelligence**:
- **Real Intelligence:** Data verified by an active, configured provider (e.g., VirusTotal, AbuseIPDB).
- **Heuristic Analysis:** Internal algorithmic evaluations (e.g., lexical entropy, regex rules, TF-IDF).
- **Demo Intelligence:** Synthetic lab simulations explicitly badged as `[Demo Intelligence]`.
- **Unavailable / Not Configured:** If an external API key is absent or a network call fails, the UI renders `Provider Not Configured` or `Geolocation Unavailable`.

---

## 3. System Architecture

```
                                  +---------------------------------------+
                                  |         Next.js 14 Web Console        |
                                  |   (Tailwind CSS, Lucide, Recharts,    |
                                  |        React Leaflet Dynamic Map)     |
                                  +-------------------+-------------------+
                                                      |
                                             REST API / JSON
                                                      |
                                  +-------------------v-------------------+
                                  |          FastAPI REST Engine          |
                                  |        (Uvicorn / Python 3.11)        |
                                  +-------------------+-------------------+
                                                      |
                   +----------------------------------+----------------------------------+
                   |                                                                     |
+------------------v------------------+                              +-------------------v-------------------+
|      20-Stage Forensic Pipeline     |                              |         Data & Persistence            |
| - MIME Parser (RFC 2047 / charsets) |                              | - SQLite Database (SQLAlchemy ORM)    |
| - Auth Analyzer (SPF/DKIM/DMARC)    |                              | - In-Memory Geolocation LRU Cache     |
| - Route Tracer (Received Reversal)  |                              | - Audit Trail & Analyst Notes         |
| - URL & Crypto Extractor            |                              +---------------------------------------+
| - Attachment Fingerprinting         |                                                  |
| - Dual-Engine NLP (TF-IDF + Rules)  |                              +-------------------v-------------------+
| - Weighted Threat Scorer (0-100)    |                              |         Export & Intelligence         |
| - ReportLab PDF & JSON Generator    |                              | - VirusTotal & AbuseIPDB Abstraction  |
+-------------------------------------+                              | - Two-Pass Formatted PDF Reports      |
                                                                     +---------------------------------------+
```

---

## 4. Key Capabilities & Forensic Innovations

| Module | Technical Implementation | Forensic Value |
| :--- | :--- | :--- |
| **Authentication Engine** | Evaluates `Authentication-Results`, `Received-SPF`, `DKIM-Signature`, and ARC headers. Calculates an independent **Header Trust Score (0–100)**. | Separates protocol compliance from content maliciousness (e.g., legitimate marketing server sending phishing vs spoofed sender). |
| **Route Reconstruction** | Parses `Received:` headers, handles RFC 2822 chronological inversion, filters internal/docnet IPs, and derives geographic coordinates. | Reconstructs the actual multi-hop relay trajectory and flags suspicious dynamic relay injection points. |
| **SSRF-Safe URL Heuristics** | Regex and DOM extraction without remote HTTP fetching. Flags IP-based URLs, anchor-text spoofing, and excessive subdomains. | Extracts indicators of compromise without exposing internal security systems to server-side request forgery or honeypot triggers. |
| **Attachment Forensics** | Computes deterministic SHA-256, SHA-1, and MD5 hashes. Identifies double extensions (`.pdf.exe`) and macro-enabled documents. | Safely fingerprints weaponized payloads without executing unverified binary code. |
| **Offline-First NLP Engine** | Dual-tier classification using scikit-learn TF-IDF model paired with regex-based social engineering detectors. | Provides instant linguistic threat scoring even in air-gapped or offline forensic environments. |
| **Explainable Scoring** | Dynamic point attribution system (0–100) with 6 sub-scores: Authentication, Sender, URL, Attachment, Content/NLP, and Infrastructure. | Every point added to the threat score is explicitly cited with forensic evidence in the UI and PDF report. |
| **SOC Case Management** | Multi-status triage (`NEW`, `IN_PROGRESS`, `REVIEWED`, `ESCALATED`, `CLOSED`), persistent analyst activity log, and case history. | Enables multi-analyst workflows, shift handovers, and compliance logging. |

---

## 5. Technology Stack

### Backend
- **Framework:** FastAPI 0.115+, Uvicorn
- **Language:** Python 3.10+ (Tested on Python 3.11.15)
- **Database:** SQLite with SQLAlchemy ORM
- **MIME & Headers:** Python built-in `email`, `email.policy`, `authres`, `dkimpy`
- **HTML & Sanitization:** BeautifulSoup4, lxml
- **Forensic PDF:** ReportLab (Two-pass `NumberedCanvas` with custom SOC styling)
- **Machine Learning & NLP:** scikit-learn (TF-IDF vectorizer + MultinomialNB), NumPy

### Frontend
- **Framework:** Next.js 14 (App Router)
- **Language:** TypeScript 5.0+
- **Styling:** Tailwind CSS (Custom SOC dark theme, glassmorphism, semantic threat badges)
- **Icons:** Lucide React
- **Visualizations:** Recharts (Area charts, bar charts, custom SVG circular gauges)
- **Mapping:** Leaflet 1.9.4, React Leaflet (SSR-safe dynamic import, CartoDB Dark Matter tiles)

---

## 6. Directory Structure

```
sih26106-threat-platform/
├── docker-compose.yml              # Multi-container orchestration (Backend + Frontend)
├── README.md                       # Comprehensive system documentation
├── .env.example                    # Template for environment configuration
├── .gitignore                      # Git ignore patterns
│
├── backend/                        # FastAPI Python 3.11 Backend
│   ├── main.py                     # Application entry point, CORS, lifespan & seed loader
│   ├── requirements.txt            # Python dependencies
│   ├── Dockerfile                  # Container definition for backend
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py               # REST API endpoints (Ingestion, Stats, Reports, Intel)
│   ├── database/
│   │   ├── database.py             # SQLAlchemy engine & session factory
│   │   ├── models.py               # ORM schemas (Investigation model)
│   │   └── crud.py                 # Persistence, query filters, telemetry aggregation
│   ├── schemas/
│   │   ├── analysis.py             # Pydantic schemas for 20-stage pipeline output
│   │   └── investigation.py        # Pydantic models for case management & API responses
│   ├── services/
│   │   ├── email_parser.py         # RFC 2822 MIME parser, RFC 2047 decoder, HTML sanitizer
│   │   ├── authentication_analyzer.py # SPF, DKIM, DMARC parser & Header Trust Scorer
│   │   ├── geo_tracer.py           # Hop reconstruction, IP classification, Haversine route
│   │   ├── url_analyzer.py         # URL heuristics, anchor mismatch, cryptocurrency detection
│   │   ├── attachment_analyzer.py  # SHA-256 hashing, dangerous/double extension detection
│   │   ├── nlp_analyzer.py         # Dual-engine NLP (TF-IDF classifier + rule-based fallback)
│   │   ├── threat_scorer.py        # Weighted 0-100 threat score & factor attribution
│   │   ├── threat_intelligence.py  # IOC reputation provider abstraction (VT, AbuseIPDB)
│   │   ├── report_generator.py     # Two-pass ReportLab PDF generator & JSON exporter
│   │   └── pipeline.py             # Fault-tolerant master pipeline orchestrator
│   ├── sample_data/                # Synthetic RFC 2822 test emails
│   │   ├── safe_email.eml          # Legitimate enterprise newsletter (Score: 0, SAFE)
│   │   ├── phishing_email.eml      # M365 credential harvesting lure (Score: 100, CRITICAL)
│   │   ├── invoice_fraud.eml       # Urgent wire transfer request (Score: 56, MEDIUM)
│   │   ├── executive_impersonation.eml # CEO gift card scam (Score: 40, MEDIUM)
│   │   ├── malware_attachment.eml  # Weaponized payload with double extension (Score: 78, HIGH)
│   │   └── auth_failure.eml        # Spoofed domain failing SPF & DMARC (Score: 50, MEDIUM)
│   └── tests/                      # Automated test suite (18 unit/integration tests)
│       ├── test_email_parser.py
│       ├── test_authentication.py
│       ├── test_received_headers.py
│       ├── test_geo_tracer.py
│       ├── test_url_analyzer.py
│       ├── test_attachment_analyzer.py
│       ├── test_nlp_analyzer.py
│       ├── test_threat_scorer.py
│       └── test_api.py
│
└── frontend/                       # Next.js 14 TypeScript Frontend
    ├── package.json
    ├── tsconfig.json
    ├── tailwind.config.ts          # SOC dark color palette
    ├── Dockerfile                  # Multi-stage container definition
    └── src/
        ├── app/                    # Next.js App Router pages
        │   ├── layout.tsx          # Master shell with Sidebar & SOC Header
        │   ├── page.tsx            # SOC Dashboard with KPI tiles & charts
        │   ├── analyze/page.tsx    # Email ingestion console (.eml upload / raw text)
        │   ├── investigations/     # Case history table with search & filters
        │   ├── investigations/[id]/ # Multi-tab forensic workspace & report export
        │   ├── geo-intelligence/   # Global relay map & IP explorer
        │   ├── threat-intelligence/# IOC query console (IP, Domain, Hash)
        │   ├── reports/            # Report repository with direct PDF/JSON download
        │   └── settings/           # System health & API provider status matrix
        ├── components/             # Reusable UI components
        │   ├── dashboard/          # Metric cards, Recharts visualizations, recent table
        │   ├── threat/             # Circular Threat Gauge & explainable factor list
        │   ├── authentication/     # SPF, DKIM, DMARC badges & Header Trust meter
        │   ├── routing/            # Hop order table & route statistics
        │   ├── map/                # SSR-safe dynamic Leaflet map with CartoDB dark tiles
        │   ├── urls/               # Suspicious URL table & cryptocurrency cards
        │   ├── attachments/        # File metadata table & SHA-256 copy action
        │   ├── nlp/                # Phishing probability gauge & keyword pills
        │   ├── investigations/     # Case triage, status dropdown & analyst notes feed
        │   └── common/             # Sidebar, Header, Notification bell
        └── lib/
            ├── api.ts              # Fetch client for all backend REST endpoints
            ├── types.ts            # TypeScript interfaces for forensic models
            └── utils.ts            # Severity color mapping & date formatters
```

---

## 7. Installation & Local Setup

### Prerequisites
- **Python:** 3.10 or 3.11 installed
- **Node.js:** v18.0.0 or v20.0.0+ with `npm`
- **Git:** Version control

### Option A: Running Locally

#### 1. Backend Setup
```bash
cd sih26106-threat-platform/backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server on port 8000
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
The backend will automatically create `email_threat.db` SQLite database and seed initial demo investigations.
- **Backend API:** `http://127.0.0.1:8000`
- **Interactive Swagger Docs:** `http://127.0.0.1:8000/docs`
- **Health Check:** `http://127.0.0.1:8000/api/health`

#### 2. Frontend Setup
```bash
cd sih26106-threat-platform/frontend

# Install dependencies
npm install

# Start Next.js development server
npm run dev
# OR for production build:
npm run build
npm start
```
The frontend will be accessible at: **`http://localhost:3000`**.

---

### Option B: Running with Docker Compose

Ensure Docker and Docker Compose are installed:
```bash
cd sih26106-threat-platform

# Build images and start all containers
docker compose up --build -d

# Check running status
docker compose ps

# View logs
docker compose logs -f
```
- **Web Interface:** `http://localhost:3000`
- **API Server:** `http://localhost:8000`

---

## 8. Environment Variables

Copy `.env.example` to `.env` in the backend directory to customize external integrations:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DATABASE_URL` | `sqlite:///./email_threat.db` | SQLAlchemy database connection string |
| `CORS_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | Allowed CORS origins (comma-separated) |
| `MAX_UPLOAD_SIZE_MB` | `10` | Maximum email payload size limit in megabytes |
| `GEO_PROVIDER` | `ip-api` | Geolocation provider (`ip-api`, `ipwhois`, `offline`) |
| `VIRUSTOTAL_API_KEY` | *(empty)* | Optional VirusTotal API key for live hash/domain lookup |
| `ABUSEIPDB_API_KEY` | *(empty)* | Optional AbuseIPDB API key for live IP reputation |
| `NLP_MODEL` | `mrm8488/bert-tiny-finetuned-sms-spam-detection` | Hugging Face model identifier (falls back to TF-IDF automatically) |

---

## 9. Comprehensive Testing

The platform includes 18 automated unit and integration tests covering the complete forensic pipeline:

```bash
cd sih26106-threat-platform/backend

# Run pytest using the virtual environment
# Linux / macOS:
PYTHONPATH=.. ./.venv/bin/pytest tests/ -v

# Windows (PowerShell):
$env:PYTHONPATH=".." ; .\.venv\Scripts\python.exe -m pytest tests\ -v
```

### Test Results Summary
```
backend/tests/test_api.py::test_health_check PASSED                                [  5%]
backend/tests/test_api.py::test_dashboard_stats PASSED                             [ 11%]
backend/tests/test_api.py::test_analyze_phishing_email PASSED                      [ 16%]
backend/tests/test_api.py::test_database_persistence_and_notes PASSED              [ 22%]
backend/tests/test_attachment_analyzer.py::test_safe_attachment PASSED              [ 27%]
backend/tests/test_attachment_analyzer.py::test_dangerous_executable PASSED        [ 33%]
backend/tests/test_attachment_analyzer.py::test_double_extension PASSED           [ 38%]
backend/tests/test_authentication.py::test_auth_headers_parsing PASSED             [ 44%]
backend/tests/test_email_parser.py::test_parse_phishing_email PASSED               [ 50%]
backend/tests/test_email_parser.py::test_rfc2047_header_decoding PASSED            [ 55%]
backend/tests/test_geo_tracer.py::test_ip_classification PASSED                    [ 61%]
backend/tests/test_geo_tracer.py::test_hop_reconstruction PASSED                   [ 66%]
backend/tests/test_nlp_analyzer.py::test_nlp_phishing_detection PASSED             [ 72%]
backend/tests/test_nlp_analyzer.py::test_nlp_benign_text PASSED                   [ 77%]
backend/tests/test_received_headers.py::test_extract_ipv4_and_ipv6 PASSED         [ 83%]
backend/tests/test_threat_scorer.py::test_threat_scorer_calculation PASSED         [ 88%]
backend/tests/test_threat_scorer.py::test_severity_thresholds PASSED              [ 94%]
backend/tests/test_url_analyzer.py::test_url_heuristic_analysis PASSED            [100%]

============================= 18 passed in 6.11s ==============================
```

---

## 10. Threat Scoring Methodology

The platform calculates a transparent, factor-attributed **Threat Score from 0 to 100**. The final score is capped at 100 and mapped to severity bands:

$$\text{Threat Score} = \min\left(100, \sum \text{Factor Points}\right)$$

### Point Attribution Schedule
| Category | Forensic Indicator | Points |
| :--- | :--- | :---: |
| **Authentication** | DMARC Verification Failure | +20 |
| | SPF Verification Failure | +15 |
| | DKIM Verification Failure | +15 |
| **Sender** | `From:` vs `Reply-To:` Address Mismatch | +10 |
| | `From:` vs `Return-Path:` Address Mismatch | +8 |
| | Display-Name Impersonation Pattern | +10 |
| | Suspicious/Lookalike Domain Pattern | +10 |
| **URLs** | Obfuscated / Heuristically Suspicious URL | +15 |
| | Anchor-Text Destination Mismatch | +15 |
| | Direct IP-based Hyperlink | +10 |
| **Attachments** | Dangerous Executable (`.exe`, `.scr`, `.bat`, etc.) | +25 |
| | Double Extension Detected (`.pdf.exe`) | +20 |
| | Macro-Enabled Document (`.docm`, `.xlsm`) | +20 |
| | Suspicious Archive File (`.zip`, `.iso`, `.img`) | +15 |
| **Content & NLP** | Credential Harvesting Language | +20 |
| | Financial Fraud / Wire Transfer Coercion | +20 |
| | Artificial Urgency / Account Takeover Pressure | +8 |
| **Infrastructure**| Suspicious Relay / Dynamic Client Injection | +15 |
| | Malformed / Anomaly in `Received:` Sequence | +8 |

### Severity Thresholds
- **0 – 19: SAFE** (Green) — Normal verified business communication
- **20 – 39: LOW** (Blue) — Minor anomalies or missing optional records
- **40 – 59: MEDIUM** (Amber) — Mismatched headers or high-entropy URLs
- **60 – 79: HIGH** (Orange) — Multiple failed authentication checks or suspicious macros
- **80 – 100: CRITICAL** (Red) — Confirmed credential phishing, spoofing, or executable payloads

---

## 11. Demonstration Workflow for Hackathon Evaluators

1. **Access Command Dashboard:** Navigate to `http://localhost:3000`. Observe live KPI cards (Total Investigations, Critical Threats, Average Score), threat distribution charts, and recent investigation feed.
2. **Launch Phishing Preset:** Click the prominent **"Try Demo"** button on the dashboard or top navigation. This immediately loads and executes the complete 20-stage forensic pipeline on `phishing_email.eml`.
3. **Inspect Threat Score Card:** Note the circular gauge registering **100 CRITICAL** and review the breakdown of the 6 sub-scores.
4. **Examine Explainable Factors:** Read the exact forensic justifications (DMARC failure, SPF failure, From/Reply-To mismatch, anchor-text spoofing, IP link, urgent language).
5. **Explore Geographic Route Map:** Scroll to the Leaflet interactive map. Inspect Hop #1 (Ashburn, US), Hop #2 (Moscow, Russia), and Hop #3 (London, UK) connected by the flight polyline.
6. **Review URL & Attachment Forensics:** Inspect the URLs table showing the anchor mismatch (`https://account.microsoft.com/...` pointing to `203.0.113.195`). Copy the attachment SHA-256 hash with one click.
7. **Examine Sanitized Body:** Switch between the Extracted Plain Text view and the Sanitized HTML view (scripts and event handlers stripped for analyst safety).
8. **Perform SOC Case Triage:** In the Case Triage section, change status from `NEW` to `IN_PROGRESS` or `ESCALATED`, add an analyst note, and observe immediate persistence.
9. **Export PDF Forensic Report:** Click **"Export PDF"** to generate and download a formal two-pass forensic document formatted for law enforcement or corporate records.
10. **Query Threat Intelligence:** Navigate to **Threat Intelligence** in the sidebar. Query IP `203.0.113.195` to view the honest attribution badge `[Demo Intelligence]`, or query an unknown domain to verify the `[Provider Not Configured]` graceful fallback.

---

## 12. Security & Privacy Architecture

- **SSRF Prevention:** The backend extracts and parses URLs using regex and BeautifulSoup without issuing outbound HTTP requests to untrusted email links.
- **HTML Sanitization:** Raw email HTML is strictly sanitized using BeautifulSoup; all `<script>`, `<iframe>`, `<object>`, `<embed>`, `<form>`, and inline `on*` JavaScript event handlers are stripped.
- **Zero Shell Execution:** Email metadata, filenames, and extracted attachments are never passed to shell interpreters or system commands.
- **Path Traversal Protection:** Filenames are sanitized with `os.path.basename` and random UUID identifiers.
- **Privacy Notice:** Email bodies and extracted payloads are kept in local storage and never sent to unconfigured external cloud APIs.

---

## 13. Limitations & Future Scope

- **Advanced Sandboxing:** Future iterations can integrate with an isolated Cuckoo or CAPEv2 sandbox for dynamic execution of suspicious attachments.
- **DKIM Cryptographic Verification:** Currently verifies DKIM signature headers and DNS selector presence; offline mode does not perform live public DNS key lookups unless network is enabled.
- **Multi-Tenant RBAC:** Can be expanded to support multi-tier SOC analyst permissions with Active Directory / LDAP authentication.

---

## 14. License

This project is developed for the **Smart India Hackathon (SIH26106)** under the auspices of AICTE and is licensed under the MIT License.
