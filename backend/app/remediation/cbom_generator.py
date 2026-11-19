import json
import uuid
from datetime import datetime

class CBOMGenerator:
    def __init__(self):
        pass

    def generate_cbom(self, findings: list) -> str:
        """
        Generate OWASP CycloneDX v1.5 JSON CBOM based on the given findings.
        """
        cbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [
                    {
                        "vendor": "NTRO",
                        "name": "SecureMailScope",
                        "version": "1.0.0"
                    }
                ]
            },
            "components": []
        }
        
        for idx, finding in enumerate(findings):
            comp = {
                "type": "cryptographic-asset",
                "bom-ref": f"crypto-asset-{idx}",
                "name": finding.get("cipher_suite", "Unknown Cipher"),
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "mode": "CBC" if "CBC" in finding.get("cipher_suite", "") else "GCM",
                        "executionEnvironment": "software-plain-ram"
                    }
                }
            }
            cbom["components"].append(comp)
            
        return json.dumps(cbom, indent=2)
