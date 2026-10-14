import os
import io
import tempfile
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

try:
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import fields, signers
    PYHANKO_SIGN_AVAILABLE = True
except ImportError:
    PYHANKO_SIGN_AVAILABLE = False


def generate_test_keys_and_cert():
    """Generates an in-memory self-signed test certificate and private key for demonstration."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Crypto Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Lab Demo Signer (Alice)"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    return cert_pem, key_pem


def create_minimal_pdf(title: str = "Lab Confidential Document", content: str = "This document is verified and signed.") -> bytes:
    """Creates a structurally valid PDF with correct xref byte offsets."""
    stream_content = (
        f"BT /F1 24 Tf 50 720 Td ({title}) Tj ET\n"
        f"BT /F1 12 Tf 50 680 Td ({content}) Tj ET"
    ).encode('latin1')

    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    obj2 = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    obj3 = (
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]"
        b" /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
    )
    obj4 = (
        b"4 0 obj\n<< /Length " + str(len(stream_content)).encode() + b" >>\n"
        b"stream\n" + stream_content + b"\nendstream\nendobj\n"
    )
    obj5 = b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"

    header = b"%PDF-1.4\n"
    body = b""
    offsets = []
    for obj in [obj1, obj2, obj3, obj4, obj5]:
        offsets.append(len(header) + len(body))
        body += obj

    xref_offset = len(header) + len(body)
    xref = b"xref\n0 6\n0000000000 65535 f \n"
    for off in offsets:
        xref += f"{off:010d} 00000 n \n".encode()

    trailer = (
        b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n"
        + str(xref_offset).encode()
        + b"\n%%EOF\n"
    )

    return header + body + xref + trailer


def create_sample_signed_pdf() -> bytes:
    """Creates a valid digitally signed PDF using pyHanko."""
    cert_pem, key_pem = generate_test_keys_and_cert()
    base_pdf = create_minimal_pdf(
        "Lab Security Research Memo",
        "Cryptographic digital signature test payload. Hash integrity verified."
    )

    if not PYHANKO_SIGN_AVAILABLE:
        return base_pdf

    # SimpleSigner.load expects file paths, so write PEM data to temp files
    with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as kf:
        kf.write(key_pem)
        key_path = kf.name
    with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as cf:
        cf.write(cert_pem)
        cert_path = cf.name

    try:
        inf = io.BytesIO(base_pdf)
        w = IncrementalPdfFileWriter(inf)
        fields.append_signature_field(
            w, sig_field_spec=fields.SigFieldSpec(sig_field_name='LabSignature_1')
        )

        signer = signers.SimpleSigner.load(
            key_file=key_path,
            cert_file=cert_path,
            key_passphrase=None
        )

        out = io.BytesIO()
        signers.sign_pdf(
            w,
            signers.PdfSignatureMetadata(field_name='LabSignature_1'),
            signer=signer,
            output=out
        )
        return out.getvalue()
    finally:
        os.unlink(key_path)
        os.unlink(cert_path)


def create_sample_tampered_pdf() -> bytes:
    """Takes a signed PDF and tampers with a single character in the body to simulate an attack."""
    signed_pdf = create_sample_signed_pdf()
    # Replace a letter in the text stream without updating the ByteRange signature
    if b"Cryptographic" in signed_pdf:
        return signed_pdf.replace(b"Cryptographic", b"MALICIOUS_MOD")
    elif b"Security" in signed_pdf:
        return signed_pdf.replace(b"Security", b"Tampered")
    # If not found, flip a byte near the start of the stream
    data_list = bytearray(signed_pdf)
    data_list[150] = (data_list[150] + 1) % 256
    return bytes(data_list)
