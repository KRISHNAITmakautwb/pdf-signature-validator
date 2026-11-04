# Lab PDF Digital Signature Sentinel

A high-assurance digital signature validation portal and REST API built for research labs. It implements **ISO 32000-1 / ISO 32000-2** and **PAdES** standards to verify document authenticity, cryptographic byte integrity, X.509 certificate trust chains, and detect PDF Shadow Attacks.

---

## 🚀 Quick Start (For Lab Members)

### Method 1: Docker / Docker Compose (Recommended for 24/7 Lab Server)

On your lab server or workstation, run:
```bash
cd pdf-signature-validator
docker compose up --build -d
```
The service will immediately become accessible to everyone in your lab network:
- **Web UI Portal**: `http://<server-ip>:8000`
- **Interactive API Docs (Swagger)**: `http://<server-ip>:8000/docs`
- **Health Check**: `http://<server-ip>:8000/api/health`

To stop:
```bash
docker compose down
```

---

### Method 2: Local Python Execution

If you prefer to run directly without Docker:
```bash
cd pdf-signature-validator
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Start the server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Or simply run:
```bash
chmod +x start.sh
./start.sh
```

---

## 💻 How Lab Members Can Use the Service

### 1. Web Portal (Drag & Drop)
Lab members open `http://<server-ip>:8000` in any web browser:
- **Drag & Drop** any PDF to inspect.
- **Download with Green Tick (✔)**: For documents showing a yellow question mark (`? "Validity Unknown"` in Adobe Reader), automatically replaces the question mark box with an official, universally visible **Green Checkmark (`✔ Signature Valid`)** display copy for printing, verification, and institutional submissions.
- **Built-in Demos**: Click *Valid Signed PDF*, *Tampered / Attack PDF*, or *Unsigned PDF* to immediately test and observe verdicts.
- **Visual ByteRange Slicer**: Inspect which bytes of the document are covered by the signature vs excluded placeholders.
- **Certificate Inspector**: View Common Name, Issuer Authority, Serial Number, and SHA-256 fingerprint.
- **Export Audit**: One-click download of the complete JSON audit or printable certificate.

---

### 2. Command Line CLI (`test_client.py`)
Lab members who write Python scripts or terminal pipelines can validate files instantly:
```bash
# Validate against local or remote lab server
python test_client.py my_paper_signed.pdf
python test_client.py --server http://lab-server.local:8000 research_agreement.pdf
```

---

### 3. Direct REST API via `curl`
```bash
curl -X POST "http://localhost:8000/api/validate" \
  -F "file=@sample_signed.pdf"
```

Sample JSON response:
```json
{
  "success": true,
  "report": {
    "filename": "sample_signed.pdf",
    "file_size_bytes": 10452,
    "is_signed": true,
    "signatures_count": 1,
    "overall_status": "VALID",
    "validation_engine": "pyHanko (PAdES ISO 32000)",
    "signatures": [
      {
        "field_name": "LabSignature_1",
        "intact": true,
        "cryptographically_valid": true,
        "is_trusted_ca": true,
        "status_verdict": "VALID",
        "certificate": {
          "subject_name": "Lab Demo Signer (Alice)",
          "issuer_name": "Crypto Lab",
          "valid_from": "2026-10-13T00:00:00",
          "valid_to": "2027-10-13T00:00:00"
        }
      }
    ],
    "anomalies": []
  }
}
```

---

## 🔒 Custom Trust Store (Lab Root CAs)
If your university or lab issues internal/self-signed certificates:
1. Place the root certificate file (`.crt`, `.pem`, `.cer`) into the `./certs/` folder, or
2. Click **"Trust Store"** in the top navigation bar of the Web UI and upload it directly.

---

## 🔬 Core Cryptographic Architecture

```
+--------------------------------------------------------------------------+
|  PDF Stream 1       | /Contents <HEX PKCS#7 CMS>      | PDF Stream 2     |
+--------------------------------------------------------------------------+
|<- [0, offset1] ---->|        (excluded from hash)     |<- [offset2,len2]>|
```

1. **ByteRange Integrity**: Slices the exact byte ranges `[0, offset1]` and `[offset2, len2]`, computes the cryptographic SHA-256 digest, and matches it against the signed `messageDigest` attribute in the CMS structure.
2. **Signature Verification**: Verifies the signer's RSA/ECDSA signature over the SignedAttributes with the embedded public key.
3. **Chain of Trust**: Validates the X.509 certificate chain against system or custom lab root certificates.
4. **Shadow Attack Detection**: Flags suspicious trailing bytes or unverified incremental updates appended after the signed ByteRange.
