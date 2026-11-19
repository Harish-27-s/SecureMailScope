# ML & Anomaly Detection (15% Audit Core)

## 1. PURPOSE
The mathematical ruleset (85%) catches deterministic configuration drift, but it cannot detect zero-day exfiltration scripts, custom mail-bombing tools, or anomalous MTA relays. The Anomaly ML Engine (15%) fills this gap using TLS Fingerprinting.

## 2. TLS FINGERPRINTING
- **JA3:** Calculates an MD5 hash of the `ClientHello` (TLS Version, Accepted Ciphers, Extensions, Elliptic Curves, Elliptic Curve Formats).
- **JA4:** (If implemented) modern multi-vector fingerprinting for stronger robustness against padding.

## 3. FEATURE VECTORIZATION
We project each TLS session into a 4-dimensional continuous space for the model:
1. `cipher_suite_strength` (Normalized integer mapping of cipher cryptographic strength).
2. `extension_count` (Number of TLS extensions offered).
3. `packet_delta_ms` (Time elapsed between `ClientHello` and `ServerHello`).
4. `version_ordinal` (Integer mapping of TLS version).

## 4. ISOLATION FOREST MODEL
We utilize an unsupervised `IsolationForest` because in 100% air-gapped networks, labeled training data of "malicious" email agents is unavailable.

### Hyperparameters:
```python
from sklearn.ensemble import IsolationForest

model = IsolationForest(
    n_estimators=100,
    max_samples='auto',
    contamination=0.1,    # Assumes ~10% of traffic might be anomalous drift
    random_state=42,
    n_jobs=-1
)
```

### Anomaly Boundary:
- The model outputs `-1` for outliers and `1` for inliers.
- Any session predicted as `-1` suffers a -100 penalty in the $M_{Anomaly}$ CSPI vector, flagging it as a potential unauthorized script or hijacked MTA relay.
