#!/usr/bin/env python3
"""
Lab Client CLI: Validate PDF Digital Signatures against the Central Lab Sentinel Service.
Usage:
    python test_client.py document.pdf
    python test_client.py --server http://192.168.1.50:8000 document.pdf
"""

import sys
import argparse
import requests
import json

def validate_pdf_remote(server_url: str, pdf_path: str):
    url = f"{server_url.rstrip('/')}/api/validate"
    print(f"Connecting to Lab Sentinel: {url}")
    print(f"Validating file: {pdf_path} ...\n")

    try:
        with open(pdf_path, 'rb') as f:
            files = {'file': (pdf_path, f, 'application/pdf')}
            response = requests.post(url, files=files, timeout=30)
    except FileNotFoundError:
        print(f"Error: File not found: {pdf_path}")
        sys.exit(1)
    except Exception as e:
        print(f"Connection error: {e}")
        sys.exit(1)

    if response.status_code != 200:
        print(f"Server error ({response.status_code}): {response.text}")
        sys.exit(1)

    result = response.json()
    if not result.get('success'):
        print(f"Validation failed: {result.get('error')}")
        sys.exit(1)

    report = result['report']
    status = report['overall_status']

    # Formatted terminal output
    status_color = "\033[92m" if status == "VALID" else ("\033[91m" if "TAMPERED" in status else "\033[93m")
    reset_color = "\033[0m"

    print("=" * 60)
    print(f" VERDICT: {status_color}{status}{reset_color}")
    print("=" * 60)
    print(f"File Name:          {report.get('filename')}")
    print(f"File Size:          {report.get('file_size_bytes')} bytes")
    print(f"Signatures Count:   {report.get('signatures_count')}")
    print(f"Validation Engine:  {report.get('validation_engine')}")
    print("-" * 60)

    for idx, sig in enumerate(report.get('signatures', [])):
        print(f"Signature #{idx + 1}: {sig.get('field_name')}")
        print(f"  - Cryptographic Byte Integrity: {'INTACT' if sig.get('intact') else 'BROKEN / TAMPERED'}")
        print(f"  - Math Signature Valid:        {'VALID' if sig.get('cryptographically_valid') else 'INVALID'}")
        print(f"  - Trust Status:                {'TRUSTED ROOT CA' if sig.get('is_trusted_ca') else 'Self-signed / Untrusted CA'}")
        
        cert = sig.get('certificate', {})
        if cert:
            print(f"  - Signer Common Name:          {cert.get('subject_name')}")
            print(f"  - Issuer Authority:            {cert.get('issuer_name')}")
            print(f"  - Validity:                    {cert.get('valid_from')} -> {cert.get('valid_to')}")
        print()

    anomalies = report.get('anomalies', [])
    if anomalies:
        print("\033[93m[!] ANOMALIES & WARNINGS:\033[0m")
        for anom in anomalies:
            print(f"  - [{anom.get('type')}] {anom.get('description')}")
    else:
        print("Security Check: No unauthorized incremental modifications detected.")

    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lab PDF Signature Sentinel CLI Validator")
    parser.add_argument("pdf_path", help="Path to the PDF file to validate")
    parser.add_argument("--server", default="http://localhost:8000", help="URL of the central lab validator service")
    args = parser.parse_args()

    validate_pdf_remote(args.server, args.pdf_path)
