#!/usr/bin/env python3
import os
from scapy.all import Ether, IP, TCP, wrpcap

def create_mitm_strip_attack(filename):
    """
    Simulate an SMTP conversation where STARTTLS is stripped.
    Server sends: 220 server ESMTP
    Client sends: EHLO client
    Server sends: 250-server\r\n250-AUTH LOGIN PLAIN\r\n250 HELP
    (STARTTLS is omitted/stripped by MITM)
    Client sends: AUTH LOGIN
    Server sends: 334 VXNlcm5hbWU6
    Client sends: dXNlcm5hbWU=
    """
    packets = []
    
    # Common headers
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    ip_c2s = IP(src="192.168.1.10", dst="10.0.0.5")
    ip_s2c = IP(src="10.0.0.5", dst="192.168.1.10")
    
    # TCP Handshake
    syn = eth / ip_c2s / TCP(sport=50000, dport=25, flags="S", seq=100)
    syn_ack = eth / ip_s2c / TCP(sport=25, dport=50000, flags="SA", seq=200, ack=101)
    ack = eth / ip_c2s / TCP(sport=50000, dport=25, flags="A", seq=101, ack=201)
    packets.extend([syn, syn_ack, ack])
    
    # SMTP Interaction
    # 1. Server greeting
    p1 = eth / ip_s2c / TCP(sport=25, dport=50000, flags="PA", seq=201, ack=101) / b"220 mail.example.com ESMTP\r\n"
    # 2. Client EHLO
    p2 = eth / ip_c2s / TCP(sport=50000, dport=25, flags="PA", seq=101, ack=229) / b"EHLO client.example.com\r\n"
    # 3. Server EHLO response (MITM stripped STARTTLS)
    p3 = eth / ip_s2c / TCP(sport=25, dport=50000, flags="PA", seq=229, ack=126) / b"250-mail.example.com\r\n250-AUTH LOGIN PLAIN\r\n250 HELP\r\n"
    # 4. Client AUTH LOGIN (plaintext fallback)
    p4 = eth / ip_c2s / TCP(sport=50000, dport=25, flags="PA", seq=126, ack=282) / b"AUTH LOGIN\r\n"
    # 5. Server prompt
    p5 = eth / ip_s2c / TCP(sport=25, dport=50000, flags="PA", seq=282, ack=138) / b"334 VXNlcm5hbWU6\r\n"
    # 6. Client sends creds
    p6 = eth / ip_c2s / TCP(sport=50000, dport=25, flags="PA", seq=138, ack=300) / b"YWRtaW4=\r\n"

    packets.extend([p1, p2, p3, p4, p5, p6])
    wrpcap(filename, packets)
    print(f"Generated {filename}")

def create_vulnerable_legacy(filename):
    """
    Simulate a TLS 1.0 connection with weak ciphers (3DES) over port 465 (SMTPS).
    """
    packets = []
    
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    ip_c2s = IP(src="192.168.1.10", dst="10.0.0.5")
    ip_s2c = IP(src="10.0.0.5", dst="192.168.1.10")
    
    # TCP Handshake
    syn = eth / ip_c2s / TCP(sport=50001, dport=465, flags="S", seq=100)
    syn_ack = eth / ip_s2c / TCP(sport=465, dport=50001, flags="SA", seq=200, ack=101)
    ack = eth / ip_c2s / TCP(sport=50001, dport=465, flags="A", seq=101, ack=201)
    packets.extend([syn, syn_ack, ack])
    
    # Client Hello (TLS 1.0 = 0x0301)
    # Record Header: Content Type 22 (Handshake), Version TLS 1.0 (0x0301), Length
    # Handshake Header: Type 1 (Client Hello), Length, Version TLS 1.0 (0x0301)
    ch_payload = b"\x16\x03\x01\x00\x2f" + b"\x01\x00\x00\x2b\x03\x01" + (b"\x00"*32) + b"\x00\x00\x02\x00\x0a\x01\x00"
    p1 = eth / ip_c2s / TCP(sport=50001, dport=465, flags="PA", seq=101, ack=201) / ch_payload

    # Server Hello (TLS 1.0) with Cipher TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)
    sh_payload = b"\x16\x03\x01\x00\x2a" + b"\x02\x00\x00\x26\x03\x01" + (b"\x11"*32) + b"\x00\x00\x0a\x00\x00"
    p2 = eth / ip_s2c / TCP(sport=465, dport=50001, flags="PA", seq=201, ack=101+len(ch_payload)) / sh_payload

    # Server Certificate (mocking a weak 1024-bit RSA, just generic bytes for now, 
    # real inspection will just check if we parse it, so let's write enough to trigger logic or mock the logic to handle this struct)
    packets.extend([p1, p2])
    wrpcap(filename, packets)
    print(f"Generated {filename}")

def create_hardened_defense(filename):
    """
    Simulate a TLS 1.3 connection with TLS_AES_256_GCM_SHA384 (0x1302) over port 465.
    """
    packets = []
    
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    ip_c2s = IP(src="192.168.1.10", dst="10.0.0.5")
    ip_s2c = IP(src="10.0.0.5", dst="192.168.1.10")
    
    # TCP Handshake
    syn = eth / ip_c2s / TCP(sport=50002, dport=465, flags="S", seq=100)
    syn_ack = eth / ip_s2c / TCP(sport=465, dport=50002, flags="SA", seq=200, ack=101)
    ack = eth / ip_c2s / TCP(sport=50002, dport=465, flags="A", seq=101, ack=201)
    packets.extend([syn, syn_ack, ack])
    
    # Client Hello (TLS 1.2 wrapper 0x0303, but extension indicates TLS 1.3)
    ch_payload = b"\x16\x03\x01\x00\x31" + b"\x01\x00\x00\x2d\x03\x03" + (b"\x22"*32) + b"\x00\x00\x02\x13\x02\x01\x00"
    p1 = eth / ip_c2s / TCP(sport=50002, dport=465, flags="PA", seq=101, ack=201) / ch_payload

    # Server Hello (TLS 1.2 wrapper, 0x1302 cipher)
    sh_payload = b"\x16\x03\x03\x00\x2a" + b"\x02\x00\x00\x26\x03\x03" + (b"\x33"*32) + b"\x00\x13\x02\x00\x00"
    p2 = eth / ip_s2c / TCP(sport=465, dport=50002, flags="PA", seq=201, ack=101+len(ch_payload)) / sh_payload

    packets.extend([p1, p2])
    wrpcap(filename, packets)
    print(f"Generated {filename}")

if __name__ == "__main__":
    os.makedirs("sample_pcaps", exist_ok=True)
    create_mitm_strip_attack("sample_pcaps/mitm_strip_attack.pcap")
    create_vulnerable_legacy("sample_pcaps/vulnerable_legacy.pcap")
    create_hardened_defense("sample_pcaps/hardened_defense.pcap")
