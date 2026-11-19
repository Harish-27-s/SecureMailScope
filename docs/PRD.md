# Product Requirements Document (PRD)

## 1. PRODUCT VISION
SecureMailScope is a sovereign, air-gapped, zero-decryption forensic framework designed to automatically evaluate the cryptographic posture and protocol resilience of email infrastructure (SMTP, IMAP, POP3).

## 2. PROBLEM STATEMENT
Legacy email MTAs (Postfix, Dovecot) frequently retain broken cryptographic ciphers (RC4, 3DES, SSLv3, TLS 1.0) and are vulnerable to active MITM `STARTTLS` stripping attacks. Security analysts lack the tools to rapidly evaluate multi-gigabyte PCAPs without manual Wireshark inspection, leading to forensic bottlenecks.

## 3. USER PERSONAS
1. **SOC Analyst (Tier 1 & 2):** Needs a 1-click dashboard to upload PCAPs and immediately see a visual risk score and anomaly flags without digging through packets.
2. **MTA Sysadmin:** Needs exact, ready-to-deploy configuration diffs (`main.cf`, `10-ssl.conf`) to patch identified vulnerabilities.
3. **CISO / Compliance Officer:** Needs executive PDF reports mapping infrastructure posture to NIST SP 800-52r2 and BSI TR-02102-2, and CycloneDX CBOMs for supply chain audits.

## 4. FUNCTIONAL REQUIREMENTS
- **FR1 (Passive Ingestion):** Ingest `.pcap` files and parse network traffic across ports 25, 465, 587, 143, 993, 110, 995 without active host agents.
- **FR2 (Zero Decryption Engine):** Analyze unencrypted TCP handshakes, `EHLO`, `STARTTLS` commands, and TLS `ClientHello`/`ServerHello` packets to assess cryptographic posture.
- **FR3 (CSPI Scoring):** Calculate the Cryptographic Security Posture Index (0-100) based on protocol, cipher, certificate, and anomaly vectors.
- **FR4 (Anomaly ML):** Compute JA3/JA4 fingerprints and cluster anomalous TLS handshakes using an unsupervised Isolation Forest.
- **FR5 (Remediation):** Generate patching diffs for Postfix and Dovecot.
- **FR6 (Export):** Generate CycloneDX v1.5 CBOM and PDF forensic audits.

## 5. NON-FUNCTIONAL REQUIREMENTS
- **NFR1 (Performance):** Complete processing of standard evaluation PCAPs in under 7 seconds.
- **NFR2 (Resource Constraints):** Consumes <150 MB RAM and <1% CPU overhead during passive listening.
- **NFR3 (Security):** 100% Air-Gapped. No external dependencies or internet telemetry during runtime.

## 6. METRICS FOR SUCCESS
- Time-to-Verdict (TTV) < 7 seconds.
- False Positive Rate for Anomaly Detection < 5%.
- 100% compliance matching with NIST SP 800-52r2.
