import dpkt
import socket

# Allowed ports for email protocols
MAIL_PORTS = {25, 465, 587, 143, 993, 110, 995}

class BPFSieve:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path

    def process(self):
        """
        Yields (timestamp, packet_data, src_ip, dst_ip, src_port, dst_port, tcp_payload)
        for packets that match the mail ports.
        """
        try:
            with open(self.pcap_path, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                for ts, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        # We only care about IP packets
                        if not isinstance(eth.data, dpkt.ip.IP):
                            continue
                        
                        ip = eth.data
                        # We only care about TCP packets
                        if not isinstance(ip.data, dpkt.tcp.TCP):
                            continue
                        
                        tcp = ip.data
                        src_port = tcp.sport
                        dst_port = tcp.dport
                        
                        if src_port in MAIL_PORTS or dst_port in MAIL_PORTS:
                            src_ip = socket.inet_ntoa(ip.src)
                            dst_ip = socket.inet_ntoa(ip.dst)
                            # Yielding relevant metadata and the full TCP object to retain sequence/ack
                            yield ts, buf, src_ip, dst_ip, src_port, dst_port, tcp
                            
                    except Exception as e:
                        # Silently skip malformed packets
                        pass
        except FileNotFoundError:
            print(f"Error: File {self.pcap_path} not found.")
            return
        except Exception as e:
            print(f"Error reading pcap: {e}")
            return
