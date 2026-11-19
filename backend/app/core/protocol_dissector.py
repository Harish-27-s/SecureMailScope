import re

class ProtocolDissector:
    def __init__(self):
        # We track state per stream key
        self.stream_states = {}

    def dissect(self, stream_key, src_ip, dst_ip, src_port, dst_port, c2s_data, s2c_data):
        if stream_key not in self.stream_states:
            self.stream_states[stream_key] = {
                'protocol': self._guess_protocol(src_port, dst_port),
                'server_offered_starttls': False,
                'client_requested_starttls': False,
                'plaintext_auth_seen': False,
                'tls_established': False,
                'stripping_detected': False
            }
        
        state = self.stream_states[stream_key]

        # Analyze Server to Client data
        s2c_str = s2c_data.decode('utf-8', errors='ignore').upper()
        if 'STARTTLS' in s2c_str:
            state['server_offered_starttls'] = True
        
        # Analyze Client to Server data
        c2s_str = c2s_data.decode('utf-8', errors='ignore').upper()
        if 'STARTTLS' in c2s_str or 'STLS' in c2s_str:
            state['client_requested_starttls'] = True
        
        # Check for plaintext auth commands
        auth_commands = ['AUTH LOGIN', 'AUTH PLAIN', 'LOGIN ', 'USER ', 'PASS ']
        for cmd in auth_commands:
            if cmd in c2s_str and not state['tls_established']:
                state['plaintext_auth_seen'] = True
                break

        # Check for TLS ClientHello magic bytes (16 03 01 or 16 03 02 etc) in c2s
        if b'\x16\x03' in c2s_data:
            state['tls_established'] = True

        # Detect Stripping:
        # If server offered it (or should have), but client authenticates in plaintext
        # In our simplified PCAP we just simulated the modified traffic (server didn't offer in the capture).
        # We'll flag stripping if plaintext auth is seen on non-implicit-TLS ports.
        if state['plaintext_auth_seen'] and state['protocol'] in ['SMTP', 'IMAP', 'POP3']:
            state['stripping_detected'] = True

        return state

    def _guess_protocol(self, sport, dport):
        port = sport if sport in [25, 465, 587, 143, 993, 110, 995] else dport
        if port in [25, 587]: return 'SMTP'
        if port == 465: return 'SMTPS'
        if port == 143: return 'IMAP'
        if port == 993: return 'IMAPS'
        if port == 110: return 'POP3'
        if port == 995: return 'POP3S'
        return 'UNKNOWN'

