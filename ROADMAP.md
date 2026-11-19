# 🗺️ ROADMAP.md — Strategic Evolution Timeline

## PHASE 1: Architectural Foundation & Simulation (Month 1)
- [x] Complete System Documentation Hydration.
- [ ] Build offline PCAP ingestion and zero-copy packet parser.
- [ ] Implement the core CSPI math engine and NIST compliance mappings.
- [ ] Test with synthetic PCAPs covering baseline, downgrade attacks, and legacy ciphers.

## PHASE 2: ML Pipeline & Closed-Loop Output (Month 2)
- [ ] Implement JA3/JA4 fingerprinting.
- [ ] Deploy the unsupervised Isolation Forest for anomaly clustering.
- [ ] Develop the Jinja2 automated remediation playbooks (Postfix, Dovecot).
- [ ] Implement OWASP CycloneDX CBOM and PDF forensic report generation.

## PHASE 3: User Interface & API Stabilization (Month 3)
- [ ] Finalize FastAPI REST endpoints and DuckDB session telemetry tracking.
- [ ] Deliver the defense command dashboard (React/Tailwind, Dark Mode).
- [ ] Conduct end-to-end integration tests with mocked PCAP uploads via UI.

## PHASE 4: Line-Rate Execution & Hardware Integration (Month 4+)
- [ ] Transition from static `.pcap` analysis to live interface sniffing (`AF_PACKET` / `libpcap`).
- [ ] Optimize memory mappings for high-throughput 10G/40G environments.
- [ ] Validate 100% air-gapped sovereign deployment protocols (Docker packaging without external dependencies).
- [ ] Jury Presentation Demo prep and final metric tuning (<7s processing target).
