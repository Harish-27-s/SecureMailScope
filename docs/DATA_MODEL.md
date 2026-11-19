# Data Model & Schema

## 1. DUCKDB SCHEMA (`session_telemetry`)
The primary storage engine is an embedded, in-memory DuckDB instance to ensure rapid, zero-copy analytics. 

```sql
CREATE TABLE IF NOT EXISTS session_telemetry (
    session_id UUID PRIMARY KEY,
    timestamp TIMESTAMP,
    src_ip VARCHAR,
    dst_ip VARCHAR,
    src_port INTEGER,
    dst_port INTEGER,
    protocol VARCHAR,
    
    -- TLS Metadata
    tls_version VARCHAR,
    cipher_suite VARCHAR,
    curve_name VARCHAR,
    
    -- Certificate Metadata
    cert_subject VARCHAR,
    cert_issuer VARCHAR,
    cert_sig_alg VARCHAR,
    cert_key_type VARCHAR,
    cert_key_length INTEGER,
    cert_not_after TIMESTAMP,
    
    -- Analysis & ML
    ja3_hash VARCHAR,
    ja4_hash VARCHAR,
    ml_outlier_score INTEGER,
    
    -- Scoring
    cspi_score FLOAT,
    downgrade_detected BOOLEAN
);
```

## 2. PYDANTIC MODELS (FastAPI Validation)

```python
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

class TLSSession(BaseModel):
    session_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    tls_version: Optional[str]
    cipher_suite: Optional[str]
    ja3_hash: Optional[str]
    cspi_score: float = Field(ge=0, le=100)
    classification: str
```
