# Cryptographic Security Posture Index (CSPI)

## 1. THE CSPI FORMULA
The CSPI is a standardized risk index (0–100) representing the cryptographic resilience of the analyzed infrastructure.

$$ CSPI = (0.35 \times P_{Protocol}) + (0.30 \times C_{Cipher}) + (0.20 \times X_{Cert}) + (0.15 \times M_{Anomaly}) $$

## 2. SCORING VECTORS & PENALTY MATRICES

### 2.1 Protocol Vector ($P_{Protocol}$) - Max 100
- **Base Score:** 100
- **Penalties:**
  - TLS 1.3 negotiated: 0 penalty
  - TLS 1.2 negotiated: -10
  - TLS 1.1 negotiated: -50
  - TLS 1.0 or SSLv3 negotiated: -100 (Critical Failure)
  - `STARTTLS` Stripping detected: -100 (Critical Failure)

### 2.2 Cipher Vector ($C_{Cipher}$) - Max 100
- **Base Score:** 100
- **Penalties:**
  - AEAD (GCM/CCM) + PFS (ECDHE): 0 penalty
  - CBC Mode Ciphers: -30
  - RC4, 3DES, or NULL ciphers: -100 (Critical Failure)
  - No Perfect Forward Secrecy (PFS): -40

### 2.3 Certificate Vector ($X_{Cert}$) - Max 100
- **Base Score:** 100
- **Penalties:**
  - RSA ≥ 2048 or ECC ≥ 256 + SHA-256+: 0 penalty
  - RSA < 2048: -60
  - SHA-1 Signature: -80
  - Expired Certificate: -100

### 2.4 Anomaly ML Vector ($M_{Anomaly}$) - Max 100
- **Base Score:** 100
- **Isolation Forest Score:** 
  - Inlier (+1): 0 penalty
  - Outlier (-1): -100

## 3. POSTURE CLASSIFICATION TIERS
Once the final CSPI is calculated, it maps to the following tiers:
- **Hardened Defense (90 - 100):** Meets all NIST/BSI requirements. No anomalies.
- **Compliant (70 - 89):** Minor drift (e.g., TLS 1.2 usage, older but acceptable ciphers).
- **Drift / Vulnerable (40 - 69):** Significant cryptographic drift (e.g., no PFS, CBC usage).
- **Critical Risk (0 - 39):** Broken cryptography (SSLv3, RC4), active MITM stripping, or malicious anomalies detected.
