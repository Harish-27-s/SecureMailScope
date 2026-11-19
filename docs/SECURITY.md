# Security Guardrails

## 1. ZERO DECRYPTION PRINCIPLE
SecureMailScope is strictly designed to evaluate the **metadata** of cryptographic sessions.
- **Rule:** The system MUST NOT import private keys (e.g., `.pem` or `.key` files belonging to the server).
- **Rule:** The system MUST NOT attempt to decrypt the TLS payload body.
- **Rule:** Any parsing logic accessing packet data beyond the TLS Handshake (Record Type 22) must immediately truncate the buffer and discard the memory.

## 2. 100% AIR-GAPPED DEPLOYMENT
Target environments include highly classified sovereign networks.
- **Rule:** No external telemetry, crash reporting (e.g., Sentry), or analytics can be included in the codebase.
- **Rule:** All dependencies must be vendored or pre-packaged into the Docker image.
- **Rule:** The Frontend Dashboard must not rely on external CDNs (e.g., Google Fonts, Tailwind CDN). All CSS and fonts must be locally served.

## 3. PASSIVE OPERATION
- **Rule:** The system runs in promiscuous mode on SPAN/TAP ports or processes static `.pcap` files.
- **Rule:** The system MUST NOT inject packets or interfere with the active TCP state of the monitored infrastructure.

## 4. DATA RETENTION
- **Rule:** `session_telemetry` stored in DuckDB is strictly in-memory (`:memory:`) or configured to aggressively purge data older than 24 hours. No persistent storage of raw packet data is permitted beyond the duration of the analysis API call.
