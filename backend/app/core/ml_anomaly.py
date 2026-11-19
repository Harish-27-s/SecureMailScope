import numpy as np
from sklearn.ensemble import IsolationForest
import hashlib

class AnomalyDetector:
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.is_fitted = False
        self.baseline_features = []

    def calculate_ja3_mock(self, c2s_data):
        """
        Creates a mock JA3 hash based on the raw client-to-server data.
        In a real scenario, this would parse the TLS ClientHello fields.
        """
        if not c2s_data:
            return "00000000000000000000000000000000"
        return hashlib.md5(c2s_data).hexdigest()

    def _extract_features(self, c2s_data, s2c_data):
        """
        Extract numerical features for the IsolationForest model.
        Features:
        1. Length of C2S data
        2. Length of S2C data
        3. Simple byte entropy of C2S
        """
        len_c2s = len(c2s_data)
        len_s2c = len(s2c_data)
        
        if len_c2s == 0:
            entropy = 0
        else:
            p, lns = np.unique(list(c2s_data), return_counts=True)
            probs = lns / len_c2s
            entropy = -np.sum(probs * np.log2(probs))
            
        return [len_c2s, len_s2c, entropy]

    def add_baseline(self, c2s_data, s2c_data):
        features = self._extract_features(c2s_data, s2c_data)
        self.baseline_features.append(features)

    def fit(self):
        # If not enough baseline data, create some dummy standard traffic data
        if len(self.baseline_features) < 10:
            for _ in range(10):
                self.baseline_features.append([500, 1500, 4.5]) # Typical standard traffic
                
        X = np.array(self.baseline_features)
        self.model.fit(X)
        self.is_fitted = True

    def predict(self, c2s_data, s2c_data):
        if not self.is_fitted:
            self.fit()
            
        features = self._extract_features(c2s_data, s2c_data)
        X = np.array([features])
        prediction = self.model.predict(X)
        # IsolationForest returns -1 for anomalies, 1 for normal
        return bool(prediction[0] == -1)
