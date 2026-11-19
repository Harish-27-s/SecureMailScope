import duckdb
import os

class DBManager:
    def __init__(self, db_path="securemailscope.duckdb"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = duckdb.connect(self.db_path)
        # We store session metrics and the overall CSPI score over time
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id UUID,
                timestamp TIMESTAMP,
                src_ip VARCHAR,
                dst_ip VARCHAR,
                src_port INTEGER,
                dst_port INTEGER,
                protocol VARCHAR,
                tls_version VARCHAR,
                cipher_suite VARCHAR,
                weak_cipher BOOLEAN,
                weak_cert BOOLEAN,
                stripping_detected BOOLEAN,
                is_anomalous BOOLEAN,
                cspi_score DOUBLE
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id UUID,
                timestamp TIMESTAMP,
                filename VARCHAR,
                overall_cspi DOUBLE
            )
        ''')
        conn.close()

    def insert_scan_job(self, job_id, filename, cspi_score):
        conn = duckdb.connect(self.db_path)
        conn.execute(
            "INSERT INTO scan_jobs VALUES (?, CURRENT_TIMESTAMP, ?, ?)",
            (job_id, filename, cspi_score)
        )
        conn.close()

    def insert_sessions(self, job_id, sessions, cspi_score):
        conn = duckdb.connect(self.db_path)
        for s in sessions:
            conn.execute('''
                INSERT INTO sessions VALUES (
                    ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
            ''', (
                job_id,
                s.get('src_ip'),
                s.get('dst_ip'),
                s.get('src_port'),
                s.get('dst_port'),
                s.get('protocol'),
                s.get('tls_version'),
                s.get('cipher_suite'),
                s.get('weak_cipher', False),
                s.get('weak_cert', False),
                s.get('stripping_detected', False),
                s.get('is_anomalous', False),
                cspi_score
            ))
        conn.close()
        
    def get_latest_sessions(self, limit=100):
        conn = duckdb.connect(self.db_path)
        res = conn.execute("SELECT * FROM sessions ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        columns = [desc[0] for desc in conn.description]
        conn.close()
        return [dict(zip(columns, row)) for row in res]
