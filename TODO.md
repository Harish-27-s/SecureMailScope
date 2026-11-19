# ✅ TODO.md — Comprehensive Development Breakdown

## 1. PARSING ENGINE (Backend)
- [ ] Implement `pcap_ingestor.py` utilizing `dpkt` for high-performance reading.
- [ ] Build BPF filter emulation to target ports 25, 465, 587, 143, 993, 110, 995.
- [ ] Implement TCP sliding-window reassembly module to handle fragmented handshakes.
- [ ] Build state machine for tracking `EHLO` -> `250-STARTTLS` -> `STARTTLS` downgrade attacks.

## 2. CRYPTOGRAPHIC ANALYSIS
- [ ] Implement TLS `ClientHello` and `ServerHello` parsers to extract JA3/JA4 components.
- [ ] Build X.509 certificate validation logic (Key lengths, Expiration, Signature Algorithms).
- [ ] Develop the deterministic rule engine enforcing NIST SP 800-52r2 and BSI TR-02102-2.

## 3. MACHINE LEARNING & ANOMALY DETECTION
- [ ] Implement robust JA3 and JA4 MD5 hashing functions.
- [ ] Design 4D feature vectorization for the TLS sessions.
- [ ] Integrate `scikit-learn` `IsolationForest(contamination=0.1)` for unsupervised clustering.
- [ ] Write threshold logic for anomaly boundary classification.

## 4. CSPI SCORING & REMEDIATION
- [ ] Implement the Cryptographic Security Posture Index (CSPI) calculation formula.
- [ ] Build Jinja2 templating engine for Postfix (`main.cf`) diffs.
- [ ] Build Jinja2 templating engine for Dovecot (`10-ssl.conf`) diffs.
- [ ] Implement OWASP CycloneDX v1.5 JSON CBOM exporter.

## 5. API & STORAGE
- [ ] Setup embedded DuckDB schema (`session_telemetry`).
- [ ] Build FastAPI endpoints: `/api/v1/analyze`, `/api/v1/patch/{service}`, `/api/v1/cbom`.
- [ ] Build PDF reporting endpoint using ReportLab.

## 6. FRONTEND DASHBOARD
- [ ] Setup React + Vite + Tailwind project.
- [ ] Implement dark-mode defense UI color tokens.
- [ ] Build CSPI gauge and metric visualization components.
- [ ] Build PCAP upload and real-time streaming view.
- [ ] Integrate 1-click remediation diff viewer.
