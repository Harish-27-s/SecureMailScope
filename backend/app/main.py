import os
import uuid
import shutil
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse, Response, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path

from backend.app.core.bpf_sieve import BPFSieve
from backend.app.core.tcp_reassembly import TCPReassembler
from backend.app.core.protocol_dissector import ProtocolDissector
from backend.app.core.crypto_dissector import CryptoDissector
from backend.app.core.ml_anomaly import AnomalyDetector
from backend.app.core.scoring_engine import CSPIScoringEngine

from backend.app.remediation.patch_generator import PatchGenerator
from backend.app.remediation.cbom_generator import CBOMGenerator
from backend.app.reporting.pdf_generator import PDFGenerator
from backend.app.database.db_manager import DBManager

app = FastAPI(title="SecureMailScope API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs("uploads", exist_ok=True)
db = DBManager()
anomaly_detector = AnomalyDetector()

@app.post("/api/v1/analyze")
async def analyze_pcap(file: UploadFile = File(...)):
    job_id = str(uuid.uuid4())
    file_path = f"uploads/{job_id}_{file.filename}"
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    sieve = BPFSieve(file_path)
    reassembler = TCPReassembler(ttl=15.0)
    protocol_dissector = ProtocolDissector()
    crypto_dissector = CryptoDissector()
    scoring_engine = CSPIScoringEngine()
    
    session_results = []
    
    # Process Packets
    for ts, buf, src_ip, dst_ip, src_port, dst_port, tcp in sieve.process():
        stream = reassembler.process_packet(ts, src_ip, dst_ip, src_port, dst_port, tcp)
        key = reassembler.get_stream_key(src_ip, dst_ip, src_port, dst_port)
        
        c2s_data = stream.c2s_buffer
        s2c_data = stream.s2c_buffer
        
        if c2s_data or s2c_data:
            # Baseline anomaly detector
            anomaly_detector.add_baseline(c2s_data, s2c_data)
            
            p_state = protocol_dissector.dissect(key, src_ip, dst_ip, src_port, dst_port, c2s_data, s2c_data)
            c_state = crypto_dissector.parse_tls(c2s_data, s2c_data)
            
            # Since we stream packets, we'll keep updating the state in a dict keyed by stream
            # For simplicity, we just rebuild the state here
            # In a real app we'd trigger this on stream close
            pass

    # Force fit the anomaly detector if it has data
    if len(anomaly_detector.baseline_features) > 0:
        anomaly_detector.fit()

    # Now evaluate all streams
    final_sessions = []
    for key, stream in reassembler.streams.items():
        c2s_data = stream.c2s_buffer
        s2c_data = stream.s2c_buffer
        
        p_state = protocol_dissector.dissect(key, stream.src_ip, stream.dst_ip, stream.src_port, stream.dst_port, c2s_data, s2c_data)
        c_state = crypto_dissector.parse_tls(c2s_data, s2c_data)
        
        is_anomalous = anomaly_detector.predict(c2s_data, s2c_data)
        
        merged = {
            "src_ip": stream.src_ip,
            "dst_ip": stream.dst_ip,
            "src_port": stream.src_port,
            "dst_port": stream.dst_port,
            "is_anomalous": is_anomalous
        }
        merged.update(p_state)
        merged.update(c_state)
        final_sessions.append(merged)
        
    cspi_score = scoring_engine.calculate_score(final_sessions)
    
    # Store to DB
    db.insert_scan_job(job_id, file.filename, cspi_score)
    db.insert_sessions(job_id, final_sessions, cspi_score)
    
    # Generate artifacts that can be downloaded later
    # In a real app we'd store these per job_id, but here we'll just keep the latest state globally or generate on the fly
    global LATEST_SESSIONS, LATEST_CSPI
    LATEST_SESSIONS = final_sessions
    LATEST_CSPI = cspi_score

    return JSONResponse(content={
        "job_id": job_id,
        "cspi_score": cspi_score,
        "sessions": final_sessions
    })

@app.get("/api/v1/patch/{service}")
async def get_patch(service: str):
    generator = PatchGenerator()
    if service == "postfix":
        diff = generator.generate_postfix_patch()
        filename = "postfix_main.cf.patch"
    elif service == "dovecot":
        diff = generator.generate_dovecot_patch()
        filename = "dovecot_10_ssl.conf.patch"
    else:
        raise HTTPException(status_code=404, detail="Service not found")
        
    return Response(
        content=diff,
        media_type="text/x-patch",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.get("/api/v1/cbom")
async def get_cbom():
    generator = CBOMGenerator()
    global LATEST_SESSIONS
    try:
        sessions = LATEST_SESSIONS
    except NameError:
        sessions = []
    
    cbom_json = generator.generate_cbom(sessions)
    return Response(
        content=cbom_json,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=crypto_bom.json"}
    )

@app.get("/api/v1/report/pdf")
async def get_report():
    generator = PDFGenerator()
    global LATEST_SESSIONS, LATEST_CSPI
    try:
        sessions = LATEST_SESSIONS
        cspi = LATEST_CSPI
    except NameError:
        sessions = []
        cspi = 100.0
        
    pdf_bytes = generator.generate_report(cspi, sessions)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=executive_report.pdf"}
    )

@app.get("/api/v1/analyze/demo/{filename}")
async def analyze_demo(filename: str):
    file_path = f"sample_pcaps/{filename}"
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Demo file not found")
        
    class MockFile:
        def __init__(self, p):
            self.filename = os.path.basename(p)
            self.file = open(p, "rb")
            
    mock_upload = MockFile(file_path)
    # Re-use logic
    return await analyze_pcap(mock_upload)

# Mount frontend
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")
