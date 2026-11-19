import time

class TCPStream:
    def __init__(self, src_ip, dst_ip, src_port, dst_port):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        # store payload fragments by sequence number
        self.c2s_data = {}  
        self.s2c_data = {}
        self.last_activity = time.time()
        self.c2s_seq = -1
        self.s2c_seq = -1
        self.c2s_buffer = bytearray()
        self.s2c_buffer = bytearray()

    def add_packet(self, ts, tcp, src_ip):
        self.last_activity = ts
        payload = tcp.data
        if not payload:
            return

        if src_ip == self.src_ip:
            self.c2s_data[tcp.seq] = payload
            if self.c2s_seq == -1:
                self.c2s_seq = tcp.seq
            # Simple linear reassembly
            while self.c2s_seq in self.c2s_data:
                chunk = self.c2s_data.pop(self.c2s_seq)
                self.c2s_buffer.extend(chunk)
                self.c2s_seq += len(chunk)
        else:
            self.s2c_data[tcp.seq] = payload
            if self.s2c_seq == -1:
                self.s2c_seq = tcp.seq
            while self.s2c_seq in self.s2c_data:
                chunk = self.s2c_data.pop(self.s2c_seq)
                self.s2c_buffer.extend(chunk)
                self.s2c_seq += len(chunk)

class TCPReassembler:
    def __init__(self, ttl=15.0):
        self.ttl = ttl
        self.streams = {}

    def get_stream_key(self, src_ip, dst_ip, src_port, dst_port):
        # normalize key directionally (smaller IP/port first)
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"

    def process_packet(self, ts, src_ip, dst_ip, src_port, dst_port, tcp):
        key = self.get_stream_key(src_ip, dst_ip, src_port, dst_port)
        if key not in self.streams:
            self.streams[key] = TCPStream(src_ip, dst_ip, src_port, dst_port)
        
        stream = self.streams[key]
        stream.add_packet(ts, tcp, src_ip)
        
        # Cleanup old streams
        self._cleanup(ts)
        return stream

    def _cleanup(self, current_ts):
        keys_to_delete = []
        for key, stream in self.streams.items():
            if current_ts - stream.last_activity > self.ttl:
                keys_to_delete.append(key)
        
        for key in keys_to_delete:
            del self.streams[key]
