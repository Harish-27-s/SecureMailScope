# Compliance Mappings

## 1. NIST SP 800-52r2 (Guidelines for the Selection, Configuration, and Use of TLS)
- **Requirement:** TLS 1.2 is the minimum requirement; TLS 1.3 is strongly recommended.
  - *Mapping:* The CSPI Protocol Vector heavily penalizes TLS 1.1 (-50) and fails TLS 1.0/SSLv3 (-100).
- **Requirement:** Servers must support (EC)DHE for Perfect Forward Secrecy.
  - *Mapping:* The CSPI Cipher Vector penalizes lack of PFS (-40).
- **Requirement:** RSA keys must be ≥ 2048 bits; ECC curves must be ≥ 256 bits (P-256 or P-384).
  - *Mapping:* The CSPI Certificate Vector penalizes weak RSA keys (-60).

## 2. IETF RFC 8996 (Deprecating TLS 1.0 and TLS 1.1)
- **Requirement:** TLS 1.0 and 1.1 must not be negotiated.
  - *Mapping:* Handshake dissector identifies these versions and directly lowers the CSPI classification to "Drift / Vulnerable".

## 3. RFC 7817 (STARTTLS in Email)
- **Requirement:** Opportunistic TLS must be attempted; active stripping attacks must be mitigated.
  - *Mapping:* The Protocol State Machine detects `STARTTLS` suppression (MITM stripping) and applies a critical failure (-100) to the CSPI.

## 4. BSI TR-02102-2 (German Federal Office for Information Security)
- **Requirement:** Stringent requirements on cipher suites (forbidding RC4, 3DES, and weak block ciphers).
  - *Mapping:* CBC mode ciphers receive a penalty (-30). RC4 and 3DES receive a critical failure (-100).
