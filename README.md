<p align="center">
  <img src="https://img.shields.io/badge/SIH%202026-PS%20SIH26159-blue?style=for-the-badge" alt="SIH Badge"/>
  <img src="https://img.shields.io/badge/Team-Ezhil-purple?style=for-the-badge" alt="Team Badge"/>
  <img src="https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=for-the-badge" alt="Status Badge"/>
</p>

<h1 align="center">🔐 SecureMailScope</h1>

<p align="center">
  <b>AI-Assisted Passive Cryptographic Posture &amp; Protocol Forensic Framework</b><br/>
  <sub>Built for NTRO | Smart India Hackathon 2026 | Problem Statement SIH26159</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.12+-3776AB?logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/scikit--learn-1.4+-F7931E?logo=scikit-learn&logoColor=white" alt="Scikit-learn"/>
  <img src="https://img.shields.io/badge/DuckDB-Embedded-FDD835?logo=duckdb&logoColor=black" alt="DuckDB"/>
  <img src="https://img.shields.io/badge/Air--Gapped-100%25-red?style=flat-square" alt="Air-Gapped"/>
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License"/>
</p>

---

## 📋 Table of Contents

- [Problem Statement](#-problem-statement)
- [Solution Overview](#-solution-overview)
- [Architecture](#-architecture)
- [CSPI Scoring Formula](#-cspi-scoring-formula)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Quick Start](#-quick-start)
- [API Reference](#-api-reference)
- [Frontend Dashboard](#-frontend-dashboard)
- [Sample PCAPs](#-sample-pcaps)
- [Algorithms Used](#-algorithms-used)
- [Security & Compliance](#-security--compliance)
- [Team](#-team)
- [License](#-license)

---

## 🎯 Problem Statement

Email protocols (SMTP, IMAP, POP3) negotiate encryption **in-flight** via `STARTTLS`, leaving sovereign defense and enterprise mail enclaves vulnerable to:

| Threat Vector | Description |
|---|---|
| **MITM STARTTLS Stripping** | On-path adversaries delete `250-STARTTLS` from server responses, forcing plaintext authentication and leaking credentials. |
| **Cryptographic Drift** | Mail servers accumulate obsolete ciphers (RC4, 3DES, CBC-mode) and weak RSA keys (<2048-bit), enabling POODLE, BEAST, and SWEET32 attacks. |
| **Forensic Bottlenecks** | Analysts spend hours manually inspecting multi-gigabyte `.pcap` files in Wireshark with no automated posture scoring. |

---

## 💡 Solution Overview

**SecureMailScope** is a **100% passive, agentless, air-gapped** forensic framework that:

- ✅ Parses network captures in **under 7 seconds**
- ✅ Scores cryptographic posture via a unified **CSPI index (0–100)**
- ✅ Detects **active STARTTLS stripping attacks** in real time
- ✅ Identifies **rogue mail agents** via unsupervised ML anomaly detection
- ✅ Generates **1-click remediation patches** for Postfix and Dovecot
- ✅ Exports **OWASP CycloneDX v1.5 CBOM** for supply-chain auditing
- ✅ Produces **executive forensic audit PDFs** with ReportLab

### Core Design Principles

| Principle | Implementation |
|---|---|
| **Zero Decryption** | Analyzes only unencrypted protocol metadata (`EHLO`, `STARTTLS`) and TLS handshake records (`ClientHello`, `ServerHello`, X.509 certs). Never inspects message payloads. |
| **Zero Host Agents** | Operates purely on `.pcap` files or tapped network streams. No software is installed on target MTAs. |
| **100% Air-Gapped** | No external internet, cloud API, or CDN dependencies. All assets bundled locally. |

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SecureMailScope                              │
│                                                                     │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────────────┐  │
│  │  .pcap   │───▶│  BPF Sieve   │───▶│  TCP Stream Reassembler  │  │
│  │  Upload   │    │  (dpkt)      │    │  (Sliding Window, 15s)   │  │
│  └──────────┘    └──────────────┘    └────────────┬─────────────┘  │
│                                                    │                │
│                          ┌─────────────────────────┼────────────┐  │
│                          │        Hybrid Audit Core              │  │
│                          │                                       │  │
│           ┌──────────────▼──────────────┐  ┌────────────────┐   │  │
│           │  85% Deterministic Engine    │  │ 15% ML Engine  │   │  │
│           │  ┌────────────────────────┐  │  │ ┌────────────┐ │   │  │
│           │  │ Protocol Dissector     │  │  │ │ JA3/JA4    │ │   │  │
│           │  │ (STARTTLS Detection)   │  │  │ │ Fingerprint│ │   │  │
│           │  ├────────────────────────┤  │  │ ├────────────┤ │   │  │
│           │  │ Crypto Dissector       │  │  │ │ Isolation  │ │   │  │
│           │  │ (TLS/X.509 Parsing)    │  │  │ │ Forest     │ │   │  │
│           │  └────────────────────────┘  │  │ └────────────┘ │   │  │
│           └──────────────┬──────────────┘  └───────┬────────┘   │  │
│                          └─────────────┬───────────┘            │  │
│                                        │                         │  │
│                          ┌─────────────▼─────────────┐          │  │
│                          │    CSPI Scoring Engine     │          │  │
│                          │    (0–100 Risk Index)      │          │  │
│                          └─────────────┬─────────────┘          │  │
│                                        │                         │  │
│           ┌────────────────────────────┼──────────────────────┐  │  │
│           │                            │                      │  │  │
│    ┌──────▼──────┐  ┌──────────▼──────────┐  ┌──────▼──────┐ │  │  │
│    │  Patch Gen  │  │   CBOM Generator    │  │  PDF Report │ │  │  │
│    │  (Jinja2)   │  │  (CycloneDX v1.5)   │  │ (ReportLab) │ │  │  │
│    └─────────────┘  └─────────────────────┘  └─────────────┘ │  │  │
│           └────────────────────────────────────────────────────┘  │  │
│                                                                     │
│    ┌────────────────┐    ┌──────────────────────────────────────┐  │
│    │  DuckDB Store  │    │  FastAPI REST API + Tailwind UI     │  │
│    │  (Columnar)    │    │  (Dark-Mode Command Dashboard)      │  │
│    └────────────────┘    └──────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📊 CSPI Scoring Formula

The **Cryptographic Security Posture Index** is a weighted composite score:

$$\text{CSPI} = (0.35 \times P_{\text{Protocol}}) + (0.30 \times C_{\text{Cipher}}) + (0.20 \times X_{\text{Cert}}) + (0.15 \times M_{\text{Anomaly}})$$

| Vector | Weight | What it Measures |
|---|---|---|
| **P (Protocol)** | 35% | STARTTLS negotiation integrity, TLS establishment |
| **C (Cipher)** | 30% | Cipher suite strength against NIST SP 800-52r2 |
| **X (Certificate)** | 20% | X.509 cert key size (RSA ≥2048 / ECC ≥256) |
| **M (Anomaly)** | 15% | ML-based anomaly score from IsolationForest |

| Score Range | Classification | Color |
|---|---|---|
| 90–100 | 🟢 **HARDENED** | Green |
| 75–89 | 🔵 **COMPLIANT** | Blue |
| 50–74 | 🟡 **MODERATE** | Yellow |
| 0–49 | 🔴 **CRITICAL** | Red |

---

## 🛠 Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Language** | Python 3.12+ | Backend, ML, Parsing |
| **Web Framework** | FastAPI + Uvicorn | Async REST API |
| **Packet Parsing** | DPKT | Zero-copy packet reading |
| **PCAP Generation** | Scapy | Synthetic test capture creation |
| **TLS Analysis** | cryptography, pyOpenSSL | X.509 cert & handshake parsing |
| **ML Engine** | scikit-learn (IsolationForest) | Unsupervised anomaly detection |
| **Database** | DuckDB (Embedded) | Columnar session metrics storage |
| **Templating** | Jinja2 | Remediation config patch generation |
| **PDF Reports** | ReportLab | Executive forensic audit PDFs |
| **CBOM** | cyclonedx-python-lib | OWASP CycloneDX v1.5 JSON export |
| **Frontend** | HTML5, Tailwind CSS, Chart.js | Dark-mode command dashboard |
| **Data Modeling** | Pydantic v2 | Strict type validation |

---

## 📁 Project Structure

```
SecureMailScope/
├── backend/
│   └── app/
│       ├── main.py                    # FastAPI application & API endpoints
│       ├── core/
│       │   ├── bpf_sieve.py           # Zero-copy DPKT packet reader (mail port filter)
│       │   ├── tcp_reassembly.py      # Sliding-window TCP stream reassembler
│       │   ├── protocol_dissector.py  # SMTP/IMAP/POP3 state machine & STARTTLS detector
│       │   ├── crypto_dissector.py    # TLS ClientHello/ServerHello & X.509 parser
│       │   ├── ml_anomaly.py          # JA3/JA4 fingerprinting & IsolationForest
│       │   └── scoring_engine.py      # CSPI score calculator (0–100)
│       ├── remediation/
│       │   ├── patch_generator.py     # Jinja2 Postfix/Dovecot config diff generator
│       │   └── cbom_generator.py      # CycloneDX v1.5 CBOM JSON builder
│       ├── reporting/
│       │   └── pdf_generator.py       # ReportLab executive PDF builder
│       ├── database/
│       │   └── db_manager.py          # DuckDB embedded columnar database
│       └── templates/
│           ├── postfix_main.cf.j2     # Hardened Postfix config template
│           └── dovecot_10_ssl.conf.j2 # Hardened Dovecot config template
├── frontend/
│   ├── index.html                     # Dashboard UI (Tailwind CSS dark mode)
│   ├── app.js                         # Vanilla JS — API calls, Chart.js gauge
│   └── style.css                      # Custom animations & scrollbar styling
├── scripts/
│   └── generate_sample_pcaps.py       # Scapy script to create test PCAPs
├── sample_pcaps/
│   ├── mitm_strip_attack.pcap         # STARTTLS stripping simulation
│   ├── vulnerable_legacy.pcap         # TLS 1.0 + 3DES weak handshake
│   └── hardened_defense.pcap          # TLS 1.3 + AES-256-GCM strong handshake
├── docs/                              # Architecture & specification documents
├── tests/                             # Unit and integration tests
├── requirements.txt                   # Python dependencies
├── .gitignore                         # Git ignore rules
├── LICENSE                            # MIT License
└── README.md                          # This file
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.12+
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/Harish-27-s/SecureMailScope.git
cd SecureMailScope

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Generate sample PCAP test files
python scripts/generate_sample_pcaps.py

# 5. Launch the server
uvicorn backend.app.main:app --reload
```

Open your browser and navigate to **http://127.0.0.1:8000** to access the Defense Command Dashboard.

---

## 📡 API Reference

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/analyze` | Upload a `.pcap` file for full cryptographic posture analysis |
| `GET` | `/api/v1/analyze/demo/{filename}` | Run analysis on a bundled sample PCAP |
| `GET` | `/api/v1/patch/postfix` | Download hardened Postfix `main.cf` diff patch |
| `GET` | `/api/v1/patch/dovecot` | Download hardened Dovecot `10-ssl.conf` diff patch |
| `GET` | `/api/v1/cbom` | Download OWASP CycloneDX v1.5 JSON CBOM |
| `GET` | `/api/v1/report/pdf` | Download executive forensic audit PDF |

### Example: Analyze a PCAP

```bash
curl -X POST -F "file=@sample_pcaps/mitm_strip_attack.pcap" http://127.0.0.1:8000/api/v1/analyze
```

### Example Response

```json
{
  "job_id": "a1b2c3d4-...",
  "cspi_score": 17.5,
  "sessions": [
    {
      "src_ip": "192.168.1.10",
      "dst_ip": "10.0.0.5",
      "dst_port": 25,
      "protocol": "SMTP",
      "tls_version": null,
      "cipher_suite": null,
      "stripping_detected": true,
      "plaintext_auth_seen": true,
      "is_anomalous": false
    }
  ]
}
```

---

## 🖥 Frontend Dashboard

The **Defense Command Dashboard** is a high-density, dark-mode cybersecurity interface featuring:

- **🎯 Drag-and-Drop Ingestion Zone** — Upload `.pcap` files or use demo quick-load buttons
- **📊 CSPI Radial Gauge** — Real-time 0–100 score with color-coded risk bands
- **📋 Protocol & Cipher Telemetry Table** — Interactive session breakdown with status badges
- **🚨 Threat Alert Banners** — Flashing critical alerts for STARTTLS stripping
- **🔧 Remediation Center** — 1-click download buttons for Postfix/Dovecot patches, CBOM, and PDF reports

---

## 🧪 Sample PCAPs

Three synthetic test captures are included for immediate demonstration:

| File | Scenario | Expected CSPI |
|---|---|---|
| `mitm_strip_attack.pcap` | SMTP STARTTLS stripped by MITM, plaintext `AUTH LOGIN` leaked | 🔴 **~17** (Critical) |
| `vulnerable_legacy.pcap` | TLS 1.0 + `TLS_RSA_WITH_3DES_EDE_CBC_SHA` + 1024-bit RSA cert | 🟡 **~50** (Moderate) |
| `hardened_defense.pcap` | TLS 1.3 + `TLS_AES_256_GCM_SHA384` + 4096-bit RSA cert | 🟢 **~100** (Hardened) |

Generate them with:
```bash
python scripts/generate_sample_pcaps.py
```

---

## 🧠 Algorithms Used

### 1. Isolation Forest (Unsupervised Anomaly Detection)
An ensemble of random decision trees that isolates anomalous observations. Since outliers are "few and different," they are isolated closer to the root of the tree, requiring fewer partitions.

- **Contamination:** `0.1` (10% expected anomaly rate)
- **Features:** Packet length, byte entropy, session size
- **Purpose:** Detect rogue mail agents, exfiltration scripts, or non-standard clients

### 2. JA3/JA4 TLS Fingerprinting
Cryptographic hash (MD5) of TLS ClientHello parameters (cipher suites, extensions, elliptic curves) to uniquely identify client implementations. Each unique client software produces a distinct fingerprint.

### 3. Deterministic Compliance Checks
Boolean evaluation of observed TLS parameters against **NIST SP 800-52r2** and **BSI TR-02102-2** baselines:
- TLS version ≥ 1.2
- Perfect Forward Secrecy (ECDHE)
- RSA key size ≥ 2048-bit / ECC ≥ 256-bit
- No deprecated ciphers (RC4, 3DES, CBC-mode)

### 4. Sliding-Window TCP Reassembly
Sequence-indexed packet reassembly with a 15-second TTL to reconstruct full bidirectional TCP streams from fragmented network captures.

### 5. Protocol State Machine
Finite state automaton tracking SMTP/IMAP/POP3 command sequences to detect protocol-level attacks (e.g., `STARTTLS` advertisement removal).

---

## 🔒 Security & Compliance

| Constraint | Status |
|---|---|
| Zero payload decryption | ✅ Enforced |
| Zero host agents installed | ✅ Enforced |
| 100% air-gapped operation | ✅ No external network calls |
| NIST SP 800-52r2 compliance checks | ✅ Implemented |
| BSI TR-02102-2 compliance checks | ✅ Implemented |
| OWASP CycloneDX v1.5 CBOM export | ✅ Implemented |
| Memory usage < 150 MB | ✅ Targeted |
| Processing time < 7 seconds | ✅ Targeted |

---

## 👥 Team

**Team Ezhil** — Smart India Hackathon 2026

Built for the **National Technical Research Organisation (NTRO)** under Problem Statement **SIH26159**.

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <sub>Built with 🛡️ by Team Ezhil for SIH 2026</sub>
</p>
