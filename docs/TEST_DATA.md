# Test Data Generation Strategies

## 1. PURPOSE
To rigorously test the 85% Math Engine and the 15% ML Engine, we require specific, highly controlled `.pcap` files. Since real classified email traffic cannot be used, we must synthesize traffic using tools like `scapy` or OpenSSL `s_client`.

## 2. SCENARIO GENERATION ALERTS

### 2.1 `hardened_defense.pcap`
- **Setup:** Use OpenSSL 1.1.1+ with `-tls1_3`.
- **Command:** `openssl s_client -connect mta.local:25 -starttls smtp -tls1_3`
- **Expected Outcome:** CSPI Score 100.

### 2.2 `vulnerable_legacy.pcap`
- **Setup:** Force older SSL versions and weak ciphers.
- **Command:** `openssl s_client -connect mta.local:25 -starttls smtp -cipher RC4-SHA -tls1`
- **Expected Outcome:** CSPI Score drops heavily due to RC4 (critical penalty) and TLS 1.0 (critical penalty).

### 2.3 `mitm_strip_attack.pcap`
- **Setup:** Requires a man-in-the-middle script (e.g., using `scapy` or `bettercap`).
- **Action:** The script intercepts the server's `250-STARTTLS` response, replaces it with `250-XXXXXXXX`, and recalculates the TCP checksum. The client attempts `AUTH LOGIN` in plaintext.
- **Expected Outcome:** Protocol state machine detects plaintext auth after EHLO without `ClientHello`. CSPI assigns a critical penalty.

## 3. PCAP VALIDATION
- All generated `.pcap` files must be saved to the `sample_pcaps/` directory.
- Pytest fixtures will iteratively load these PCAPs and assert the expected CSPI vector outputs.
