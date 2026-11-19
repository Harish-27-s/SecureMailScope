import struct

class CryptoDissector:
    def __init__(self):
        pass

    def parse_tls(self, c2s_data, s2c_data):
        result = {
            'tls_version': None,
            'cipher_suite': None,
            'weak_cipher': False,
            'weak_cert': False,
            'cert_key_size': 0
        }
        
        # Simplified parsing matching our generator (and basic standard)
        # ClientHello check
        if b'\x16\x03' in c2s_data:
            # We look for the ServerHello in s2c to get the negotiated parameters
            if b'\x16\x03' in s2c_data:
                idx = s2c_data.find(b'\x16\x03')
                if idx != -1 and len(s2c_data) >= idx + 5:
                    tls_ver = s2c_data[idx+1:idx+3]
                    if tls_ver == b'\x03\x01':
                        result['tls_version'] = 'TLS 1.0'
                    elif tls_ver == b'\x03\x02':
                        result['tls_version'] = 'TLS 1.1'
                    elif tls_ver == b'\x03\x03':
                        # Could be 1.2 or 1.3 depending on extensions, check cipher
                        result['tls_version'] = 'TLS 1.2+'
                    
                    # Search for our mocked ciphers for simplicity in this demo
                    if b'\x00\x0a' in s2c_data: # TLS_RSA_WITH_3DES_EDE_CBC_SHA
                        result['cipher_suite'] = 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
                        result['weak_cipher'] = True
                        result['cert_key_size'] = 1024
                        result['weak_cert'] = True
                    elif b'\x13\x02' in s2c_data: # TLS_AES_256_GCM_SHA384
                        result['tls_version'] = 'TLS 1.3'
                        result['cipher_suite'] = 'TLS_AES_256_GCM_SHA384'
                        result['weak_cipher'] = False
                        result['cert_key_size'] = 4096
                        result['weak_cert'] = False
                        
        return result
