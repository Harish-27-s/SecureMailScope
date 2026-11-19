# UI/UX Dashboard Layout

## 1. DESIGN SYSTEM (Air-Gapped & High-Density)
- **Theme:** Strict Dark Mode (defense posture).
- **Font Stack:** System fonts (Inter, Roboto, SF Pro) ensuring zero external CDN calls.
- **Color Tokens:**
  - Background: `slate-900` (#0f172a)
  - Panel Surface: `slate-800` (#1e293b)
  - Critical / Vulnerable: `rose-500` (#f43f5e)
  - Compliant / Hardened: `emerald-400` (#34d399)
  - Drift / Warning: `amber-400` (#fbbf24)
  - Typography: `slate-300` / `white`

## 2. MAIN SCREENS

### 2.1 The Command View (Dashboard)
- **Top Bar:** "SecureMailScope" logo, Server Status (Online/Offline), Upload PCAP Drag & Drop Zone.
- **Hero Section (Left):** CSPI Radial Gauge (0-100). Large numerical score with dynamic color tiering.
- **Hero Section (Right):** "Cryptographic Health" summary. Four horizontal progress bars corresponding to the 4 vectors (Protocol, Cipher, Cert, Anomaly).
- **Bottom Section:** Data Table of "Parsed Sessions". Columns: Session ID, Src IP, Dst IP, Protocol, TLS Version, Classification (Badge).

### 2.2 The Session Detail View (Modal / Slide-over)
- Triggers when clicking a row in the Session Table.
- Displays raw extracted metadata: `ClientHello` bytes, JA3 hash, Certificate Issuer.
- Highlights exact reasons for CSPI penalties.

### 2.3 The Remediation View
- "Generate Patch" button inside the Session Detail View.
- Renders a monospaced code-block showing a Jinja2 generated standard Unix diff (red minuses, green pluses) for `main.cf` or `10-ssl.conf`.
- "Download Patch" and "Export CBOM" buttons.
