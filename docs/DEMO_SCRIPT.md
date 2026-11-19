# Jury Demo Script (3-Minute Presentation)

## PRE-REQUISITES
- SecureMailScope Docker containers running (Backend + Frontend).
- UI Dashboard open in a full-screen browser window on Dark Mode.
- Three test `.pcap` files loaded on the Desktop:
  1. `hardened_defense.pcap` (Perfect TLS 1.3 traffic).
  2. `vulnerable_legacy.pcap` (SSLv3, RC4 ciphers, expired cert).
  3. `mitm_strip_attack.pcap` (Active downgrade to plaintext).

## SCRIPT

### 0:00 - 0:45: The Problem & Vision
"Email transport is the weakest link in defense networks. Today, an analyst must spend hours in Wireshark parsing multi-gigabyte PCAPs to identify if MTAs are using deprecated crypto or falling victim to STARTTLS downgrade attacks. We built SecureMailScope: a 100% air-gapped, zero-decryption forensic engine that does this mathematically in under 7 seconds."

### 0:45 - 1:30: Demo 1 (Hardened vs Vulnerable)
*(Drag and drop `hardened_defense.pcap` into UI)*
"Notice the immediate response. The parsing engine processes the packets without touching payloads. CSPI Score is 100. It maps perfectly to NIST SP 800-52r2."

*(Drag and drop `vulnerable_legacy.pcap` into UI)*
"Now look at this MTA. Score drops to 32. The deterministic engine immediately flags RC4 ciphers and an expired certificate. On the right, click 'Generate Patch'. We instantly output a `main.cf` Postfix diff to harden the server."

### 1:30 - 2:15: Demo 2 (MITM & ML Anomaly)
*(Drag and drop `mitm_strip_attack.pcap` into UI)*
"Here is an active threat. An on-path adversary stripped the STARTTLS advertisement. Our protocol state machine catches this silently falling back to plaintext and issues a Critical Alert. Furthermore, our unsupervised Isolation Forest flagged the JA3 fingerprint of the client as highly anomalous compared to standard Postfix/Exchange servers—identifying the custom exfiltration script."

### 2:15 - 3:00: Closing & Export
"Because we are zero-decryption, we maintain payload privacy. Because we are agentless, deployment is instantaneous on SPAN ports. Finally, click 'Export CBOM'—generating an OWASP CycloneDX cryptographic bill of materials for supply chain audits. SecureMailScope bridges the gap between passive detection and active patching."
