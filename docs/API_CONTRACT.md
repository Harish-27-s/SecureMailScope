# REST API Contracts

## Base URL: `/api/v1`

---

## 1. Analyze PCAP
**Endpoint:** `POST /analyze`
**Content-Type:** `multipart/form-data`

### Request Parameters
- `file` (File): The uploaded `.pcap` file.

### Response `200 OK`
```json
{
  "status": "success",
  "processing_time_ms": 1450,
  "summary": {
    "total_sessions": 150,
    "cspi_score": 82.5,
    "classification": "Compliant"
  },
  "vectors": {
    "protocol_score": 90,
    "cipher_score": 70,
    "cert_score": 100,
    "anomaly_score": 100
  },
  "alerts": [
    {
      "severity": "high",
      "type": "CIPHER_DRIFT",
      "description": "CBC mode cipher suite detected in session 42."
    }
  ]
}
```

---

## 2. Generate Remediation Patch
**Endpoint:** `GET /patch/{service}`
**Path Parameters:**
- `service` (string): `postfix` or `dovecot`

### Response `200 OK`
```json
{
  "service": "postfix",
  "filename": "main.cf",
  "patch_diff": "--- old/main.cf\n+++ new/main.cf\n- smtpd_tls_protocols = !SSLv2, !SSLv3\n+ smtpd_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1\n+ tls_high_cipherlist = ECDHE-ECDSA-AES128-GCM-SHA256:..."
}
```

---

## 3. Export CBOM
**Endpoint:** `GET /cbom`

### Response `200 OK`
**Content-Type:** `application/json`
Returns an OWASP CycloneDX v1.5 compliant JSON object detailing all identified cryptographic algorithms, key lengths, and protocols.

---

## 4. Export Forensic Report
**Endpoint:** `GET /report/pdf`

### Response `200 OK`
**Content-Type:** `application/pdf`
Returns a dynamically generated ReportLab PDF containing executive summaries, CSPI breakdowns, and remediation steps.
