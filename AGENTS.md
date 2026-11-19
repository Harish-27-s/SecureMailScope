# 🏛️ AGENTS.md — Global System Directives

## 1. PROJECT IDENTITY
- **System:** SecureMailScope (SIH26159 by NTRO, Team Ezhil)
- **Role:** AI-Assisted Passive Cryptographic Posture & Protocol Forensic Framework
- **Primary Objective:** Deliver an ultra-fast, air-gapped forensic engine that strictly evaluates network protocol and cryptographic posture without compromising payload integrity.

## 2. OPERATIONAL BOUNDARIES & RED ZONES
- **Zero Decryption Principle:** The system MUST NEVER attempt to decrypt, reassemble, or inspect the payload bodies of email traffic. Analysis is strictly confined to unencrypted protocol negotiation (e.g., SMTP `EHLO`, `STARTTLS`) and public TLS handshake metadata (`ClientHello`, `ServerHello`, X.509 Certificates).
- **Zero Host Agents:** The framework is 100% passive and agentless. It operates purely on `.pcap` files or tapped network streams. No software agents are installed on the target Mail Transfer Agents (MTAs).
- **100% Air-Gapped:** The system is designed for sovereign defense and critical national infrastructure. It must NEVER reach out to external internet endpoints, cloud APIs, or CDNs for operation. All assets, models, and dependencies are locally bundled.

## 3. ARCHITECTURAL PILLARS
- **85% Deterministic Math / 15% Anomaly ML Hybrid Audit Core:**
  - **Deterministic Engine (85%):** Mathematical boolean evaluation of TLS parameters against NIST SP 800-52r2 and BSI TR-02102-2. Enforces TLS 1.3/1.2, ECDHE Perfect Forward Secrecy, and RSA ≥2048-bit / ECC ≥256-bit parameters.
  - **Anomaly ML Engine (15%):** Uses JA3/JA4 TLS client fingerprinting and an unsupervised `IsolationForest(contamination=0.1)` to cluster and isolate non-standard mail agents or exfiltration scripts without requiring labeled training datasets.
- **Closed-Loop Remediation:** The system doesn't just alert; it generates ready-to-deploy configuration diff files for Postfix (`main.cf`) and Dovecot (`10-ssl.conf`), bridging the gap between detection and patching.
- **Cryptographic Bill of Materials (CBOM):** Full export of cryptographic assets via OWASP CycloneDX v1.5 JSON to support supply-chain security auditing.

## 4. AGENT RESPONSIBILITIES
- All AI Agents operating in this repository must stringently adhere to these constraints.
- Any generated code must assume an air-gapped execution environment.
- Code patterns must emphasize extremely high performance, zero-copy memory management (where applicable), and strict typing.
