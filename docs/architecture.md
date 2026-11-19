# Architecture Blueprint

## 1. SYSTEM OVERVIEW
SecureMailScope is built on a high-throughput, memory-efficient pipeline designed to passively sieve network traffic, evaluate cryptographic metadata without payload inspection, and generate deterministic compliance reports and remediation outputs.

## 2. CORE COMPONENTS

### 2.1 Zero-Copy BPF Sieve & TCP Reassembly
- **Ingestion:** Utilizes `dpkt` to parse `.pcap` files sequentially.
- **BPF Filtering:** Emulates BPF logic to exclusively process frames destined for or originating from email transport ports (25, 465, 587, 143, 993, 110, 995).
- **TCP Sliding Window:** Manages out-of-order packets and fragmentation, ensuring complete protocol commands (like `STARTTLS`) and TLS Handshake segments are accurately reconstructed before analysis.

### 2.2 Protocol State Machine
- **State Tracking:** Maps connection states per 5-tuple (SrcIP, DstIP, SrcPort, DstPort, Protocol).
- **STARTTLS Downgrade Detection:** Tracks `EHLO` response `250-STARTTLS`. If a subsequent authentication occurs in plaintext without a `ClientHello`, the state machine flags a MITM Downgrade / Stripping attack.

### 2.3 Cryptographic Dissector
- **TLS Hello Parsing:** Extracts TLS versions, Cipher Suites, Compression Methods, and Extensions (e.g., SNI, ALPN) from `ClientHello` and `ServerHello`.
- **Certificate Validation:** Parses X.509 Certificates to evaluate signature algorithms (e.g., rejecting SHA-1), RSA/ECC key lengths, and validity periods.

### 2.4 Hybrid Audit Engine (Math & ML)
- **Math Engine (85%):** Deterministic boolean evaluations against NIST SP 800-52r2 arrays.
- **ML Engine (15%):** Calculates JA3/JA4 MD5 hashes and vectorizes the metadata. An `IsolationForest` predicts whether the handshake is an outlier.

### 2.5 Storage & API (DuckDB + FastAPI)
- **Embedded DuckDB:** Ephemeral, in-memory SQL execution for fast aggregation of `session_telemetry`.
- **FastAPI:** Exposes the analytical output and remediation triggers via REST.

## 3. DATA FLOW
1. `PCAP` Upload -> FastAPI (`/api/v1/analyze`).
2. FastAPI -> `pcap_ingestor` (DPKT parsing).
3. Packets -> TCP Reassembly -> Protocol State Machine -> Cryptographic Dissector.
4. Metadata -> Math Engine & ML Engine.
5. Scores & Anomalies -> DuckDB `session_telemetry`.
6. DuckDB Aggregation -> API Response (CSPI Score, CBOM, Patches).
