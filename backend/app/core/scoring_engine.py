class CSPIScoringEngine:
    def __init__(self):
        pass

    def calculate_score(self, session_results):
        """
        Calculate CSPI Score (0-100) based on formula:
        CSPI = (0.35 * P_Protocol) + (0.30 * C_Cipher) + (0.20 * X_Cert) + (0.15 * M_Anomaly)
        """
        if not session_results:
            return 100.0 # Default perfect score if no traffic

        total_sessions = len(session_results)
        
        # Aggregate scores
        protocol_score = 0
        cipher_score = 0
        cert_score = 0
        anomaly_score = 0

        for res in session_results:
            # Protocol: Stripping detected = 0, TLS established = 100, else (e.g. standard plaintext not stripped but bad practice) = 50
            if res.get('stripping_detected', False):
                p_score = 0
            elif res.get('tls_established', False):
                p_score = 100
            else:
                p_score = 50
                
            # Cipher: Weak cipher = 0, TLS 1.3/strong = 100, unknown TLS = 80
            if res.get('weak_cipher', False):
                c_score = 0
            elif res.get('tls_version') == 'TLS 1.3':
                c_score = 100
            elif res.get('tls_version') in ['TLS 1.2', 'TLS 1.2+']:
                c_score = 80
            else:
                c_score = 50 # Plaintext or unknown
                
            # Cert: Weak cert (e.g. < 2048 bit RSA) = 0, >=2048 = 100, unknown = 50
            if res.get('weak_cert', False):
                x_score = 0
            elif res.get('cert_key_size', 0) >= 2048:
                x_score = 100
            else:
                x_score = 50
                
            # Anomaly: Anomalous = 0, Normal = 100
            if res.get('is_anomalous', False):
                a_score = 0
            else:
                a_score = 100
                
            protocol_score += p_score
            cipher_score += c_score
            cert_score += x_score
            anomaly_score += a_score

        # Averages
        avg_p = protocol_score / total_sessions
        avg_c = cipher_score / total_sessions
        avg_x = cert_score / total_sessions
        avg_m = anomaly_score / total_sessions

        cspi = (0.35 * avg_p) + (0.30 * avg_c) + (0.20 * avg_x) + (0.15 * avg_m)
        return round(cspi, 2)
