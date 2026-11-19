# 📡 CONTEXT.md — Living Architecture & Memory

## 1. CURRENT STATE
- **Project Phase:** Core Foundation & Architecture Hydration.
- **Objective:** Establishing the skeletal structure and comprehensive technical specifications for SecureMailScope.
- **Technical Debt:** Currently none. System is in greenfield hydration phase.

## 2. ARCHITECTURE SNAPSHOT
- **Ingestion Layer:** DPKT-based zero-copy packet reader with BPF port filtering (25, 465, 587, 143, 993, 110, 995).
- **Analysis Layer:** 
  - TLS Handshake dissector (`ClientHello`, `ServerHello`, Certs).
  - ML Pipeline for JA3/JA4 fingerprinting and Isolation Forest scoring.
- **Storage Layer:** Embedded DuckDB for ephemeral, in-memory `session_telemetry` tracking.
- **API Layer:** FastAPI REST interface.
- **Frontend Layer:** React/Tailwind dark mode dashboard (Air-gapped, zero CDN).

## 3. CRITICAL MILESTONES
- [ ] Milestone 1: Documentation & Specification Hydration (In Progress).
- [ ] Milestone 2: PCAP Ingestion & Parsing Engine implementation.
- [ ] Milestone 3: Cryptographic Posture Scoring (CSPI) & ML Anomaly Detection pipeline.
- [ ] Milestone 4: Config Remediation & CBOM Generation.
- [ ] Milestone 5: UI/UX Dashboard Integration.
- [ ] Milestone 6: Hardware TAP Line-Rate Integration and End-to-End Testing.

## 4. EVOLUTION NOTES
- This document is a living memory of the system. Agents should refer to this to understand the high-level trajectory and current maturity of the framework.
