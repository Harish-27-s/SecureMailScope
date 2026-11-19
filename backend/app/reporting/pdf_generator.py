from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io

class PDFGenerator:
    def __init__(self):
        pass

    def generate_report(self, cspi_score, session_metrics):
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, 750, "SecureMailScope: Executive Forensic Audit Report")
        
        c.setFont("Helvetica", 12)
        c.drawString(50, 710, f"Overall CSPI Score: {cspi_score}/100")
        
        y = 670
        c.drawString(50, y, "Session Findings:")
        y -= 30
        
        for idx, session in enumerate(session_metrics):
            if y < 100:
                c.showPage()
                c.setFont("Helvetica", 12)
                y = 750
            
            c.drawString(70, y, f"Session {idx+1}: {session.get('src_ip')} -> {session.get('dst_ip')}:{session.get('dst_port')}")
            y -= 20
            c.drawString(90, y, f"Protocol: {session.get('protocol')}")
            y -= 20
            c.drawString(90, y, f"TLS Version: {session.get('tls_version')}")
            y -= 20
            c.drawString(90, y, f"Cipher: {session.get('cipher_suite')}")
            y -= 20
            stripping = "Yes" if session.get('stripping_detected') else "No"
            c.drawString(90, y, f"STARTTLS Stripped: {stripping}")
            y -= 30

        c.save()
        buffer.seek(0)
        return buffer.getvalue()
