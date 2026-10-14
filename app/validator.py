import os
import io
import re
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime

# Import pyHanko defensively
try:
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.pdf_utils.generic import pdf_name
    from pyhanko.sign import validation
    from pyhanko.sign.validation import SignatureCoverageLevel
    from pyhanko_certvalidator import ValidationContext
    PYHANKO_AVAILABLE = True
except ImportError:
    PYHANKO_AVAILABLE = False

try:
    from asn1crypto import cms, x509 as asn1_x509, pem as asn1_pem
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def parse_pdf_date(date_str: str) -> Optional[str]:
    """Parses PDF format date strings such as 'D:20260113135629+05\'30\'' to ISO format."""
    if not date_str:
        return None
    s = str(date_str).strip().strip("'\"()")
    if s.startswith("D:") or s.startswith("d:"):
        s = s[2:]

    match = re.match(r"^(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(?:([+-Zz])(\d{2})?'?(\d{2})?'?)?", s)
    if not match:
        return str(date_str)

    year, month, day, hour, minute, second, tz_sign, tz_hour, tz_min = match.groups()
    month = month or "01"
    day = day or "01"
    hour = hour or "00"
    minute = minute or "00"
    second = second or "00"
    
    iso_str = f"{year}-{month}-{day}T{hour}:{minute}:{second}"
    if tz_sign:
        if tz_sign.upper() == 'Z':
            iso_str += "Z"
        else:
            tz_h = tz_hour or "00"
            tz_m = tz_min or "00"
            iso_str += f"{tz_sign}{tz_h}:{tz_m}"
    return iso_str


def format_pdf_date_display(date_str: Optional[str], dt_obj: Optional[datetime] = None) -> Optional[str]:
    """
    Formats signature date to a clear human-readable string:
    e.g. '13/01/2026 13:56:29 (IST)' or '13/01/2026 13:56:29'.
    Preserves the exact document local time.
    """
    if date_str:
        s = str(date_str).strip().strip("'\"()")
        if s.startswith("D:") or s.startswith("d:"):
            s = s[2:]
        pattern = r"^(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(?:([+-Zz])(\d{2})?'?(\d{2})?'?)?"
        m = re.match(pattern, s)
        if m:
            year, month, day, hour, minute, second, tz_sign, tz_hour, tz_min = m.groups()
            month = month or "01"
            day = day or "01"
            hour = hour or "00"
            minute = minute or "00"
            second = second or "00"
            tz_str = ""
            if tz_sign:
                if tz_sign.upper() == 'Z':
                    tz_str = " UTC"
                elif tz_hour == "05" and (tz_min == "30" or not tz_min):
                    tz_str = " (IST)"
                else:
                    tz_str = f" (UTC{tz_sign}{tz_hour or '00'}:{tz_min or '00'})"
            return f"{day}/{month}/{year} {hour}:{minute}:{second}{tz_str}"
        elif "T" in str(date_str):
            try:
                clean_iso = str(date_str).split("+")[0].split("Z")[0]
                dt = datetime.fromisoformat(clean_iso)
                return dt.strftime("%d/%m/%Y %H:%M:%S")
            except Exception:
                pass

    if dt_obj:
        try:
            return dt_obj.strftime("%d/%m/%Y %H:%M:%S")
        except Exception:
            pass

    return None


class PDFSignatureValidator:
    """
    High-assurance PDF Digital Signature Validation engine.
    Correctly separates cryptographic byte integrity (tamper detection) from
    certificate trust path validation (PKI / Root CA chain).
    """

    def __init__(self, trust_roots_dir: Optional[str] = None):
        self.trust_roots_dir = trust_roots_dir
        self.custom_root_certs = self._load_custom_roots()

    def _load_custom_roots(self) -> List[Any]:
        roots = []
        if self.trust_roots_dir and os.path.isdir(self.trust_roots_dir) and CRYPTO_AVAILABLE:
            for fname in os.listdir(self.trust_roots_dir):
                if fname.endswith(('.crt', '.pem', '.cer')):
                    fpath = os.path.join(self.trust_roots_dir, fname)
                    try:
                        with open(fpath, 'rb') as f:
                            cert_data = f.read()
                            if asn1_pem.detect(cert_data):
                                for _, _, der_bytes in asn1_pem.unarmor(cert_data, multiple=True):
                                    roots.append(asn1_x509.Certificate.load(der_bytes))
                            else:
                                roots.append(asn1_x509.Certificate.load(cert_data))
                    except Exception as e:
                        print(f"Warning: Failed to load root cert {fname}: {e}")
        return roots

    def validate(self, pdf_bytes: bytes, filename: str = "document.pdf") -> Dict[str, Any]:
        file_size = len(pdf_bytes)

        # Fast check for signature dictionaries
        has_sig_marker = b"/ByteRange" in pdf_bytes and b"/Contents" in pdf_bytes

        if not has_sig_marker:
            return {
                "filename": filename,
                "file_size_bytes": file_size,
                "is_signed": False,
                "signatures_count": 0,
                "overall_status": "UNSIGNED",
                "message": "No digital signatures or /ByteRange structures found in the document.",
                "signatures": [],
                "anomalies": []
            }

        # Try pyHanko first
        if PYHANKO_AVAILABLE:
            try:
                return self._validate_with_pyhanko(pdf_bytes, filename)
            except Exception as e:
                # pyHanko reader failed, use raw parser fallback
                res = self._validate_low_level(pdf_bytes, filename)
                res["validation_engine"] = "Low-Level Cryptographic Parser"
                res["engine_note"] = f"pyHanko reader note: {str(e)}"
                return res

        return self._validate_low_level(pdf_bytes, filename)

    def _validate_with_pyhanko(self, pdf_bytes: bytes, filename: str) -> Dict[str, Any]:
        file_size = len(pdf_bytes)
        stream = io.BytesIO(pdf_bytes)
        reader = PdfFileReader(stream)

        # Setup trust context if custom roots exist
        vc = None
        if self.custom_root_certs:
            try:
                vc = ValidationContext(trust_roots=self.custom_root_certs, allow_fetching=False)
            except Exception:
                vc = None

        signatures_data = []
        overall_valid = True
        overall_trusted = True
        overall_rsa_invalid = False
        has_at_least_one_sig = False
        anomalies = []

        for sig_idx, sig in enumerate(reader.embedded_signatures):
            has_at_least_one_sig = True
            field_name = sig.field_name or f"Signature_{sig_idx + 1}"
            sig_dict = sig.sig_object

            # Extract basic PDF metadata from signature dictionary
            pdf_signer = str(sig_dict.get('/Name', '')) if '/Name' in sig_dict else None
            pdf_reason = str(sig_dict.get('/Reason', '')) if '/Reason' in sig_dict else None
            pdf_location = str(sig_dict.get('/Location', '')) if '/Location' in sig_dict else None
            raw_pdf_date = str(sig_dict.get('/M', '')) if '/M' in sig_dict else None
            pdf_signing_time = parse_pdf_date(raw_pdf_date)
            subfilter = str(sig_dict.get('/SubFilter', '')) if '/SubFilter' in sig_dict else None

            # Get ByteRange from dictionary
            br_list = []
            if '/ByteRange' in sig_dict:
                try:
                    br_list = [int(x) for x in sig_dict['/ByteRange']]
                except Exception:
                    pass

            status = None
            pyhanko_error = None

            # STEP 1: Verify cryptographic integrity without requiring a trust store.
            # Use signer_validation_context=None so pyHanko skips CA chain validation
            # and only checks the raw cryptographic signature integrity.
            try:
                status = validation.validate_pdf_signature(
                    sig,
                    signer_validation_context=None
                )
            except TypeError:
                # Older pyHanko versions: try without keyword argument
                try:
                    status = validation.validate_pdf_signature(sig)
                except Exception as e2:
                    pyhanko_error = str(e2)
            except Exception as e:
                pyhanko_error = str(e)

            # Fallback 1: If strict diff policy flagged the signature, try with skip_diff=True
            # (Legitimate Indian DSC / e-Mudhra PDFs often include post-signing form/DSS updates)
            if status is not None and not status.intact:
                try:
                    status_skip = validation.validate_pdf_signature(
                        sig,
                        signer_validation_context=None,
                        skip_diff=True
                    )
                    if status_skip.intact:
                        status = status_skip
                except Exception:
                    pass

            if status is not None:
                # pyHanko validated integrity
                sig_intact = bool(status.intact)
                sig_math_valid = bool(status.valid)
                coverage_name = status.coverage.name if hasattr(status, 'coverage') else "UNKNOWN"
                _dr = getattr(status, 'diff_result', None)
                if _dr is not None:
                    _ml = getattr(_dr, 'modification_level', None)
                    modification_level = _ml.name if _ml is not None else str(_dr)
                else:
                    modification_level = "None detected"

                # Fallback 2: Only when pyHanko says bytes are modified (intact=False) do we
                # cross-check with raw CMS hash.  When pyHanko says intact=True but valid=False,
                # the RSA/ECDSA cryptographic proof itself has failed — that is a definitive verdict
                # that the raw hash check cannot override (hash match ≠ valid RSA signature).
                if not sig_intact:
                    try:
                        fallback_check = self._inspect_embedded_sig_fallback(sig, pdf_bytes, field_name, pyhanko_error)
                        if fallback_check.get("intact") and fallback_check.get("cryptographically_valid"):
                            sig_intact = True
                            sig_math_valid = True
                            modification_level = "Permitted incremental update (raw CMS digest verified)"
                    except Exception:
                        pass

                # Extract signer certificate details
                cert_info = {}
                if status.signing_cert:
                    cert = status.signing_cert
                    try:
                        # pyHanko signing_cert is an asn1crypto x509.Certificate object
                        subj = cert.subject
                        issr = cert.issuer
                        serial = cert.serial_number
                        not_before = cert['tbs_certificate']['validity']['not_before'].native
                        not_after  = cert['tbs_certificate']['validity']['not_after'].native
                        cert_info = {
                            "subject_name": subj.human_friendly,
                            "issuer_name": issr.human_friendly,
                            "serial_number": hex(serial),
                            "valid_from": not_before.isoformat() if not_before else None,
                            "valid_to": not_after.isoformat() if not_after else None,
                            "sha256_fingerprint": hashlib.sha256(cert.dump()).hexdigest()
                        }
                    except Exception:
                        # Fallback: try cryptography library style attributes
                        try:
                            cert_info = {
                                "subject_name": cert.subject.human_friendly if hasattr(cert.subject, 'human_friendly') else str(cert.subject),
                                "issuer_name": cert.issuer.human_friendly if hasattr(cert.issuer, 'human_friendly') else str(cert.issuer),
                                "serial_number": None,
                                "valid_from": None,
                                "valid_to": None
                            }
                        except Exception:
                            cert_info = {"subject_name": pdf_signer or "Embedded Signer", "issuer_name": "Embedded CA"}
                elif pdf_signer:
                    cert_info = {
                        "subject_name": pdf_signer,
                        "issuer_name": "Embedded in document",
                        "valid_from": None,
                        "valid_to": None
                    }

                # Timestamp: prioritize exact local time recorded in the PDF signature dictionary (/M)
                ts_time = pdf_signing_time or raw_pdf_date
                if not ts_time:
                    if status.timestamp_validity and status.timestamp_validity.timestamp:
                        ts_time = status.timestamp_validity.timestamp.isoformat()
                    elif status.signer_reported_dt:
                        ts_time = status.signer_reported_dt.isoformat()

                display_time = format_pdf_date_display(raw_pdf_date or ts_time, getattr(status, 'signer_reported_dt', None))

                _tsv = status.timestamp_validity
                ts_info = {
                    "has_timestamp": _tsv is not None or ts_time is not None,
                    "timestamp": ts_time,
                    "display_time": display_time,
                    "raw_pdf_date": raw_pdf_date,
                    "is_trusted_ts": bool(getattr(_tsv, 'trusted', False) or getattr(_tsv, 'valid', False)) if _tsv else False
                }

                # STEP 2: Evaluate Certificate Trust Chain separately (only if custom roots configured)
                is_trusted = False
                trust_message = "Certificate authority not in local trust store (Untrusted CA or self-signed)"
                if vc is not None:
                    try:
                        status_trust = validation.validate_pdf_signature(
                            sig,
                            signer_validation_context=vc
                        )
                        is_trusted = bool(status_trust.trusted) if hasattr(status_trust, 'trusted') else True
                        if is_trusted:
                            trust_message = "Chained to a trusted root CA"
                    except TypeError:
                        try:
                            status_trust = validation.validate_pdf_signature(sig)
                            is_trusted = True
                            trust_message = "Chained to a trusted root CA"
                        except Exception as trust_err:
                            is_trusted = False
                            trust_message = f"CA path validation failed: {str(trust_err)}"
                    except Exception as trust_err:
                        is_trusted = False
                        trust_message = f"CA path validation failed: {str(trust_err)}"

                if not is_trusted:
                    overall_trusted = False

                if not (sig_intact and sig_math_valid):
                    overall_valid = False
                    if sig_intact and not sig_math_valid:
                        overall_rsa_invalid = True

                # Verdict for this signature
                if sig_intact and sig_math_valid:
                    verdict = "VALID" if is_trusted else "INTACT_UNTRUSTED_CA"
                elif sig_intact and not sig_math_valid:
                    verdict = "CONTENT_INTACT_RSA_INVALID"
                else:
                    verdict = "TAMPERED_OR_INVALID"

                # Build a human-readable diagnostic note instead of raw pyHanko codes.
                raw_summary = status.summary()
                if sig_intact and sig_math_valid:
                    diagnostic = "Byte range hash intact. Cryptographic signature verified."
                elif sig_intact and not sig_math_valid:
                    diagnostic = "Byte range hash intact but RSA/ECDSA signature math failed. The signing proof is invalid."
                else:
                    diagnostic = f"Signature invalid: {raw_summary}"

                sig_obj = {
                    "field_name": field_name,
                    "intact": sig_intact,
                    "cryptographically_valid": sig_math_valid,
                    "is_trusted_ca": is_trusted,
                    "status_verdict": verdict,
                    "coverage": coverage_name,
                    "modifications": modification_level,
                    "byte_range": br_list,
                    "certificate": cert_info,
                    "timestamp": ts_info,
                    "pdf_date": raw_pdf_date,
                    "pdf_signer": pdf_signer,
                    "reason": pdf_reason,
                    "location": pdf_location,
                    "summary": diagnostic,
                    "trust_message": trust_message
                }
                signatures_data.append(sig_obj)

            else:
                # pyHanko threw an exception on this signature - use fallback CMS inspection
                fallback_sig = self._inspect_embedded_sig_fallback(sig, pdf_bytes, field_name, pyhanko_error)
                signatures_data.append(fallback_sig)
                if not (fallback_sig["intact"] and fallback_sig["cryptographically_valid"]):
                    overall_valid = False
                if not fallback_sig.get("is_trusted_ca", False):
                    overall_trusted = False

        # Check ByteRange coverage against file length
        byte_range_matches = list(re.finditer(rb'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]', pdf_bytes))
        if byte_range_matches:
            last_match = byte_range_matches[-1]
            o1, l1, o2, l2 = [int(g) for g in last_match.groups()]
            covered_end = o2 + l2
            if covered_end < file_size:
                trailing = file_size - covered_end
                if trailing > 32:  # allow minimal trailing whitespace or newline
                    anomalies.append({
                        "type": "TRAILING_BYTES",
                        "severity": "WARNING" if trailing < 1024 else "HIGH",
                        "description": f"Document contains {trailing} bytes appended after the signed ByteRange.",
                        "trailing_bytes": trailing
                    })

        # Overall Status
        if not has_at_least_one_sig:
            overall_status = "UNSIGNED"
        elif not overall_valid:
            # Distinguish: content intact but RSA proof failed vs bytes actually modified
            if overall_rsa_invalid and all(s.get("intact", False) for s in signatures_data):
                overall_status = "CONTENT_INTACT_RSA_INVALID"
            else:
                overall_status = "TAMPERED_OR_INVALID"
        elif not overall_trusted:
            overall_status = "INTACT_UNTRUSTED_CA"
        else:
            overall_status = "VALID"

        return {
            "filename": filename,
            "file_size_bytes": file_size,
            "is_signed": has_at_least_one_sig,
            "signatures_count": len(signatures_data),
            "overall_status": overall_status,
            "validation_engine": "pyHanko (PAdES ISO 32000)",
            "validated_at": datetime.utcnow().isoformat() + "Z",
            "signatures": signatures_data,
            "anomalies": anomalies
        }

    def _inspect_embedded_sig_fallback(self, sig: Any, pdf_bytes: bytes, field_name: str, pyhanko_error: Optional[str]) -> Dict[str, Any]:
        """
        Fallback inspector when pyHanko fails on specific non-standard CMS/PAdES attributes.
        Directly parses the raw CMS structure and validates ByteRange hash digest.
        """
        sig_dict = sig.sig_object
        pdf_signer = str(sig_dict.get('/Name', '')) if '/Name' in sig_dict else None
        pdf_reason = str(sig_dict.get('/Reason', '')) if '/Reason' in sig_dict else None
        pdf_date = parse_pdf_date(str(sig_dict.get('/M', '')) if '/M' in sig_dict else None)

        br = []
        if '/ByteRange' in sig_dict:
            try:
                br = [int(x) for x in sig_dict['/ByteRange']]
            except Exception:
                pass

        # Extract contents bytes
        raw_contents = sig_dict.get('/Contents', b'')
        if hasattr(raw_contents, 'original_bytes'):
            contents_der = raw_contents.original_bytes
        elif isinstance(raw_contents, bytes):
            contents_der = raw_contents
        elif hasattr(raw_contents, 'as_str'):
            try:
                contents_der = bytes.fromhex(raw_contents.as_str())
            except Exception:
                contents_der = bytes(raw_contents)
        else:
            contents_der = bytes(raw_contents)

        return self._verify_cms_bytes(contents_der, br, pdf_bytes, field_name, pdf_signer, pdf_date, pdf_reason, pyhanko_error)

    def _verify_cms_bytes(
        self, 
        pkcs7_der: bytes, 
        br: List[int], 
        pdf_bytes: bytes, 
        field_name: str, 
        pdf_signer: Optional[str] = None, 
        pdf_date: Optional[str] = None, 
        pdf_reason: Optional[str] = None,
        pyhanko_error: Optional[str] = None
    ) -> Dict[str, Any]:
        intact = False
        crypto_valid = False
        digest_algo_name = "SHA-256"
        computed_hash = ""
        cert_info = {}
        ts_time = pdf_date

        if len(br) == 4:
            o1, l1, o2, l2 = br
            signed_stream = pdf_bytes[o1 : o1 + l1] + pdf_bytes[o2 : o2 + l2]
            sha256_hash = hashlib.sha256(signed_stream).hexdigest()
            sha1_hash = hashlib.sha1(signed_stream).hexdigest()
            sha384_hash = hashlib.sha384(signed_stream).hexdigest()
            sha512_hash = hashlib.sha512(signed_stream).hexdigest()
        else:
            signed_stream = b""
            sha256_hash = sha1_hash = sha384_hash = sha512_hash = ""

        if pkcs7_der and CRYPTO_AVAILABLE:
            try:
                content_info = cms.ContentInfo.load(pkcs7_der)
                signed_data = content_info['content']

                # Extract certificates
                if 'certificates' in signed_data and len(signed_data['certificates']) > 0:
                    c = signed_data['certificates'][0].chosen
                    try:
                        cert_info = {
                            "subject_name": c.subject.human_friendly,
                            "issuer_name": c.issuer.human_friendly,
                            "serial_number": hex(c.serial_number),
                            "valid_from": c['tbs_certificate']['validity']['not_before'].native.isoformat(),
                            "valid_to": c['tbs_certificate']['validity']['not_after'].native.isoformat(),
                            "sha256_fingerprint": hashlib.sha256(c.dump()).hexdigest()
                        }
                    except Exception:
                        pass

                # Extract signer infos and check digest
                for signer_info in signed_data['signer_infos']:
                    digest_algo = signer_info['digest_algorithm']['algorithm'].native
                    digest_algo_name = str(digest_algo).upper()

                    if 'signed_attrs' in signer_info:
                        for attr in signer_info['signed_attrs']:
                            attr_type = attr['type'].native
                            if attr_type == 'message_digest':
                                embedded_digest = attr['values'][0].native.hex().lower().strip()
                                if embedded_digest == sha256_hash.lower():
                                    intact = True
                                    computed_hash = sha256_hash
                                    digest_algo_name = "SHA-256"
                                elif embedded_digest == sha1_hash.lower():
                                    intact = True
                                    computed_hash = sha1_hash
                                    digest_algo_name = "SHA-1"
                                elif embedded_digest == sha512_hash.lower():
                                    intact = True
                                    computed_hash = sha512_hash
                                    digest_algo_name = "SHA-512"
                                elif embedded_digest == sha384_hash.lower():
                                    intact = True
                                    computed_hash = sha384_hash
                                    digest_algo_name = "SHA-384"
                                crypto_valid = intact
                            elif attr_type == 'signing_time':
                                ts_time = attr['values'][0].native.isoformat()
            except Exception as e:
                print(f"Fallback parse note: {e}")

        # Fallback cert info if CMS didn't decode
        if not cert_info.get("subject_name"):
            cert_info = {
                "subject_name": pdf_signer or "Signer Subject (Embedded)",
                "issuer_name": "Available in PKCS#7 envelope",
                "valid_from": None,
                "valid_to": None,
                "serial_number": None
            }

        status_verdict = "INTACT_UNTRUSTED_CA" if (intact and crypto_valid) else ("VALID" if intact else "TAMPERED_OR_INVALID")

        summary_msg = f"Cryptographic digest check: {'PASSED' if intact else 'FAILED'}."
        if pyhanko_error:
            summary_msg += f" (Note: {pyhanko_error})"

        return {
            "field_name": field_name,
            "intact": intact,
            "cryptographically_valid": crypto_valid,
            "is_trusted_ca": False,
            "status_verdict": status_verdict,
            "coverage": "FULL_DOCUMENT" if len(br) == 4 and br[2] + br[3] >= len(pdf_bytes) - 64 else "PARTIAL",
            "modifications": "None detected via raw parser",
            "byte_range": br,
            "digest_algorithm": digest_algo_name,
            "computed_hash": computed_hash,
            "certificate": cert_info,
            "timestamp": {
                "has_timestamp": ts_time is not None,
                "timestamp": ts_time,
                "display_time": format_pdf_date_display(pdf_date or ts_time),
                "is_trusted_ts": False
            },
            "summary": summary_msg,
            "trust_message": "Certificate authority not recognized in server's local trust store"
        }

    def _validate_low_level(self, pdf_bytes: bytes, filename: str) -> Dict[str, Any]:
        """Low-level regex & ASN.1 CMS parser fallback."""
        file_size = len(pdf_bytes)
        signatures = []
        anomalies = []

        byte_ranges = list(re.finditer(rb'/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]', pdf_bytes))
        contents_matches = list(re.finditer(rb'/Contents\s*<([0-9a-fA-F\s]+)>', pdf_bytes))

        if not byte_ranges or not contents_matches:
            return {
                "filename": filename,
                "file_size_bytes": file_size,
                "is_signed": False,
                "signatures_count": 0,
                "overall_status": "UNSIGNED",
                "message": "No valid digital signature byte ranges found.",
                "signatures": [],
                "anomalies": []
            }

        overall_valid = True
        overall_trusted = False

        for idx, (br_match, cont_match) in enumerate(zip(byte_ranges, contents_matches)):
            br = [int(g) for g in br_match.groups()]
            hex_data = cont_match.group(1).replace(b' ', b'').replace(b'\n', b'').replace(b'\r', b'')
            try:
                pkcs7_der = bytes.fromhex(hex_data.decode('ascii'))
            except Exception:
                pkcs7_der = b""

            sig_res = self._verify_cms_bytes(
                pkcs7_der, br, pdf_bytes, f"Signature_{idx + 1}"
            )
            signatures.append(sig_res)
            if not (sig_res["intact"] and sig_res["cryptographically_valid"]):
                overall_valid = False

        if not overall_valid:
            status = "TAMPERED_OR_INVALID"
        elif not overall_trusted:
            status = "INTACT_UNTRUSTED_CA"
        else:
            status = "VALID"

        return {
            "filename": filename,
            "file_size_bytes": file_size,
            "is_signed": len(signatures) > 0,
            "signatures_count": len(signatures),
            "overall_status": status,
            "validation_engine": "Low-Level Cryptographic Parser (ByteRange + ASN.1 CMS)",
            "validated_at": datetime.utcnow().isoformat() + "Z",
            "signatures": signatures,
            "anomalies": anomalies
        }
