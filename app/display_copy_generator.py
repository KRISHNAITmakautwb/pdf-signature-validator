import io
import hashlib
import datetime
import re
from typing import Dict, Any, Optional, List, Tuple
import pypdf
from reportlab.pdfgen import canvas
from reportlab.lib import colors


def find_signature_locations(reader: pypdf.PdfReader) -> List[Tuple[int, List[float], str, int, Dict[str, str]]]:
    """
    Scans a PDF reader for interactive signature fields / annotations.
    Returns: (page_index, rect [x0, y0, x1, y1], field_name, page_rotation, widget_metadata).
    """
    locations = []
    try:
        for page_idx, page in enumerate(reader.pages):
            annots = page.get("/Annots")
            if not annots:
                continue

            try:
                annot_list = annots.get_object() if hasattr(annots, "get_object") else annots
            except Exception:
                continue

            page_rot = int(page.get("/Rotate", 0) or 0) % 360

            for annot_ref in annot_list:
                try:
                    annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                    if not isinstance(annot, dict):
                        continue

                    is_sig = (annot.get("/FT") == "/Sig") or (annot.get("/Subtype") == "/Widget" and annot.get("/FT") == "/Sig")
                    if not is_sig and annot.get("/Subtype") == "/Widget":
                        parent = annot.get("/Parent")
                        if parent:
                            parent_obj = parent.get_object() if hasattr(parent, "get_object") else parent
                            if isinstance(parent_obj, dict) and parent_obj.get("/FT") == "/Sig":
                                is_sig = True

                    if is_sig:
                        rect = annot.get("/Rect")
                        if rect and len(rect) == 4:
                            r = [float(val) for val in rect]
                            w = abs(r[2] - r[0])
                            h = abs(r[3] - r[1])
                            if w > 10 and h > 10:
                                name = str(annot.get("/T") or "")

                                # Extract exact metadata from signature dictionary /V if attached
                                widget_meta = {}
                                v_dict = annot.get("/V")
                                if hasattr(v_dict, "get_object"):
                                    v_dict = v_dict.get_object()
                                if isinstance(v_dict, dict):
                                    if "/Name" in v_dict:
                                        widget_meta["name"] = str(v_dict["/Name"])
                                    if "/M" in v_dict:
                                        widget_meta["date"] = str(v_dict["/M"])
                                    if "/Reason" in v_dict:
                                        widget_meta["reason"] = str(v_dict["/Reason"])
                                    if "/Location" in v_dict:
                                        widget_meta["location"] = str(v_dict["/Location"])

                                locations.append((page_idx, r, name, page_rot, widget_meta))
                except Exception:
                    continue
    except Exception:
        pass

    return locations


def clean_signer_name(raw_name: str) -> str:
    """Extracts a clean personal or entity name from certificate subject DN."""
    if not raw_name:
        return "Authorized Signer"
    name = raw_name.strip()
    if "Common Name:" in name:
        name = name.split("Common Name:")[1].split(",")[0].strip()
    elif "CN=" in name:
        name = name.split("CN=")[1].split(",")[0].strip()
    elif "," in name:
        name = name.split(",")[0].strip()
    return name.strip() or "Authorized Signer"


def format_signature_date(dt_str: Optional[str]) -> str:
    """
    Formats signature date to DD-Mon-YYYY HH:MM:SS (e.g. '05-Sep-2022 14:07:17').
    Preserves exact local time (IST) from the document without shifting to UTC.
    """
    if not dt_str:
        return datetime.datetime.now().strftime("%d-%b-%Y %H:%M:%S")

    # 1. PDF ASN.1 format: D:YYYYMMDDHHMMSS+HH'MM'
    if dt_str.startswith("D:"):
        raw = dt_str[2:].replace("'", "").replace("+", "").replace("-", "")
        for fmt, length in [("%Y%m%d%H%M%S", 14), ("%Y%m%d%H%M", 12), ("%Y%m%d", 8)]:
            try:
                dt = datetime.datetime.strptime(raw[:length], fmt)
                return dt.strftime("%d-%b-%Y %H:%M:%S")
            except Exception:
                pass

    # 2. ISO format (e.g. 2022-09-05T14:07:17+05:30)
    try:
        clean = dt_str.strip()
        if clean.endswith("Z"):
            dt_utc = datetime.datetime.fromisoformat(clean.replace("Z", "+00:00"))
            dt_ist = dt_utc + datetime.timedelta(hours=5, minutes=30)
            return dt_ist.strftime("%d-%b-%Y %H:%M:%S")

        dt = datetime.datetime.fromisoformat(clean)
        return dt.strftime("%d-%b-%Y %H:%M:%S")
    except Exception:
        pass

    # 3. Standard date patterns
    for fmt in (
        "%d-%b-%Y %H:%M:%S",
        "%d-%B-%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y, %I:%M:%S %p",
        "%d/%m/%Y, %I:%M:%S %p",
        "%Y.%m.%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            dt = datetime.datetime.strptime(dt_str.strip(), fmt)
            return dt.strftime("%d-%b-%Y %H:%M:%S")
        except Exception:
            pass

    return dt_str


def fit_text_line(c: canvas.Canvas, text: str, font_name: str, base_size: float, max_width: float) -> Tuple[str, float]:
    """
    Ensures text never overflows past max_width by applying common government abbreviations,
    dynamic font scaling down to 5.0pt, or clean truncation with ellipsis.
    """
    # 1. Smart abbreviations for common long authorities / reasons
    t = text
    t = t.replace("Ministry of Electronics and Information Technology", "Ministry of Electronics & IT")
    t = t.replace("National Academic Depository", "NAD")
    t = t.replace("Department of Higher Education", "Dept of Higher Ed")

    cur_size = base_size
    w = c.stringWidth(t, font_name, cur_size)
    if w <= max_width:
        return t, cur_size

    # 2. Scale font down proportionally (down to 5.0 pt minimum)
    scaled_size = max(5.0, cur_size * (max_width / w))
    w_scaled = c.stringWidth(t, font_name, scaled_size)
    if w_scaled <= max_width:
        return t, scaled_size

    # 3. Truncate with ellipsis if still too wide
    while len(t) > 8 and c.stringWidth(t + "…", font_name, 5.0) > max_width:
        t = t[:-1]
    return t + "…", 5.0


def create_green_tick_stamp(
    page_width: float,
    page_height: float,
    rect: List[float],
    signer_name: str,
    signing_time: str,
    original_sha256: str,
    reason: Optional[str] = None,
    location: Optional[str] = None,
    page_rotation: int = 0
) -> bytes:
    """
    Generates the standard verified signature stamp:
      - Automatically rotates to stay upright on rotated pages (/Rotate 90, 180, 270)
      - Stays strictly within page margins without spilling off the edge
      - Positions safely to avoid overlapping centered main certificate text
      - Automatically wraps/fits long names and reasons to never bleed outside the box
      - Renders 'Signature valid' in serif font (Times-Roman)
      - Bold 3D green checkmark with black drop shadow
      - Standard metadata block: Digitally Signed, Name, Date, Reason, Location
    """
    packet = io.BytesIO()
    c = canvas.Canvas(packet, pagesize=(page_width, page_height))

    margin = 16.0
    rot = page_rotation % 360

    # Effective visual width and height of the page
    if rot in (90, 270):
        eff_pw = page_height
        eff_ph = page_width
    else:
        eff_pw = page_width
        eff_ph = page_height

    # Standard compact stamp size (fits cleanly in margin without overlapping center text)
    stamp_w = 142.0
    stamp_h = 44.0

    raw_x0 = min(rect[0], rect[2])
    raw_x1 = max(rect[0], rect[2])
    raw_y0 = min(rect[1], rect[3])
    raw_y1 = max(rect[1], rect[3])

    # Convert user space coordinates to visual screen coordinates
    if rot == 90:
        vis_x0 = raw_y0
        vis_y0 = page_width - raw_x1
    elif rot == 180:
        vis_x0 = page_width - raw_x1
        vis_y0 = page_height - raw_y1
    elif rot == 270:
        vis_x0 = page_height - raw_y1
        vis_y0 = raw_x0
    else:
        vis_x0 = raw_x0
        vis_y0 = raw_y0

    # Position at the natural signature coordinates where the signer placed it on the page
    # Clamp inside page margins so it never bleeds off the page edges
    safe_vis_x = min(vis_x0, eff_pw - margin - stamp_w)
    safe_vis_x = max(margin, safe_vis_x)
    safe_vis_y = min(max(vis_y0, margin), eff_ph - margin - stamp_h)

    # Translate and rotate canvas so drawing is strictly local (0, 0) -> (stamp_w, stamp_h)
    if rot == 90:
        user_x = page_width - safe_vis_y
        user_y = safe_vis_x
        c.saveState()
        c.translate(user_x, user_y)
        c.rotate(90)
    elif rot == 180:
        user_x = page_width - safe_vis_x
        user_y = page_height - safe_vis_y
        c.saveState()
        c.translate(user_x, user_y)
        c.rotate(180)
    elif rot == 270:
        user_x = safe_vis_y
        user_y = page_height - safe_vis_x
        c.saveState()
        c.translate(user_x, user_y)
        c.rotate(270)
    else:
        c.saveState()
        c.translate(safe_vis_x, safe_vis_y)

    # 1. 100% TRANSPARENT BACKGROUND (No white fill)
    # The signature is transparent with page content: text, lines and seals underneath show through completely!

    # 2. 3D Bold Green Checkmark with Black Drop Shadow
    tx = 3.0
    max_text_w = stamp_w - tx - 2.0
    vx = tx + 50.0
    vy = 7.5

    check_coords = [
        (vx - 14.5, vy + 14.5), # Left tip outer
        (vx,        vy),        # Outer vertex
        (vx + 20.0, vy + 33.0), # Top-right outer tip
        (vx + 15.0, vy + 36.0), # Top-right inner corner
        (vx,        vy + 7.0),  # Inner vertex
        (vx - 11.5, vy + 17.5), # Left tip inner
    ]

    # Black drop shadow
    sh_dx = 1.3
    sh_dy = -1.3
    p_shadow = c.beginPath()
    p_shadow.moveTo(check_coords[0][0] + sh_dx, check_coords[0][1] + sh_dy)
    for px, py in check_coords[1:]:
        p_shadow.lineTo(px + sh_dx, py + sh_dy)
    p_shadow.close()
    c.setFillColor(colors.black)
    c.drawPath(p_shadow, fill=1, stroke=0)

    # Vivid green checkmark body
    p_green = c.beginPath()
    p_green.moveTo(check_coords[0][0], check_coords[0][1])
    for px, py in check_coords[1:]:
        p_green.lineTo(px, py)
    p_green.close()
    c.setFillColor(colors.HexColor("#00A83E"))
    c.drawPath(p_green, fill=1, stroke=0)

    # 3. Exact Signature Text Layout (Preserve original content without fabricating fields)
    clean_name = clean_signer_name(signer_name)
    formatted_date = format_signature_date(signing_time)

    c.setFillColor(colors.black)

    # Header: "Signature valid" in Serif (Times-Roman)
    c.setFont("Times-Roman", 10.5)
    c.drawString(tx, stamp_h - 10.0, "Signature valid")

    # Strictly preserve actual document content (do not fabricate missing fields)
    lines_to_draw = []
    lines_to_draw.append(f"Digitally signed by {clean_name}")

    if reason and reason.strip() and reason.strip().lower() not in ("none", "null"):
        lines_to_draw.append(f"Reason: {reason.strip()}")

    if location and location.strip() and location.strip().lower() not in ("none", "null"):
        lines_to_draw.append(f"Location: {location.strip()}")

    lines_to_draw.append(f"Date: {formatted_date}")

    # Draw the dynamic lines with auto-fit
    cur_y = stamp_h - 10.0 - 7.0
    for line_text in lines_to_draw:
        text_fitted, font_sz = fit_text_line(c, line_text, "Helvetica", 6.2, max_text_w)
        c.setFont("Helvetica", font_sz)
        c.drawString(tx, cur_y, text_fitted)
        cur_y -= 6.8

    c.restoreState()
    c.save()
    packet.seek(0)
    return packet.getvalue()


def generate_verified_display_copy(
    pdf_bytes: bytes,
    validation_report: Dict[str, Any]
) -> bytes:
    """
    Transforms a cryptographically intact digitally signed PDF into
    a 'Verified Display Copy' with the official upright Green Tick stamp (✔).
    """
    if not validation_report.get("is_signed"):
        raise ValueError("Cannot generate verified display copy: Document contains no digital signatures.")

    signatures = validation_report.get("signatures", [])
    if not signatures:
        raise ValueError("Cannot generate verified display copy: No signature objects found.")

    primary_sig = signatures[0]
    if not primary_sig.get("intact", False):
        raise ValueError("Cannot generate verified display copy: Signature integrity check failed (Document was modified or corrupted).")

    # Extract metadata from validation report
    cert_info = primary_sig.get("certificate", {})
    timestamp_info = primary_sig.get("timestamp", {})

    base_signer_name = primary_sig.get("pdf_signer") or cert_info.get("subject_name", "Authorized Signer")
    base_signing_time = primary_sig.get("pdf_date") or timestamp_info.get("raw_pdf_date") or timestamp_info.get("timestamp") or ""
    base_reason = primary_sig.get("reason")
    base_location = primary_sig.get("location")
    original_sha256 = primary_sig.get("computed_hash") or hashlib.sha256(pdf_bytes).hexdigest()

    # Parse document with PyPDF
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    writer = pypdf.PdfWriter()

    # Locate signature annotations with exact bounds, rotation, and widget metadata
    sig_locations = find_signature_locations(reader)

    target_stamps = {} # page_idx -> (rect, page_rot, widget_meta)
    num_pages = len(reader.pages)

    if sig_locations:
        for page_idx, rect, name, page_rot, widget_meta in sig_locations:
            if page_idx < num_pages:
                target_stamps[page_idx] = (rect, page_rot, widget_meta)
    else:
        # Fallback if no visual widget found: place in clear bottom right
        last_page_idx = num_pages - 1
        page_box = reader.pages[last_page_idx].mediabox
        pw = float(page_box.width)
        ph = float(page_box.height)
        page_rot = int(reader.pages[last_page_idx].get("/Rotate", 0) or 0) % 360
        target_stamps[last_page_idx] = ([pw - 175.0, 30.0, pw - 20.0, 80.0], page_rot, {})

    # Merge overlays onto pages
    for page_idx, page in enumerate(reader.pages):
        # Remove signature widget annotations entirely from each page.
        # Keeping them (even without /AP) lets strict PDF validators traverse
        # /Annots, find the /FT /Sig entry, and flag the modified bytes as tampered.
        # pypdf's ArrayObject must be modified in-place; key reassignment fails.
        if "/Annots" in page:
            try:
                annot_list = page["/Annots"]
                if hasattr(annot_list, "get_object"):
                    annot_list = annot_list.get_object()
                sig_indices = []
                for i, annot_ref in enumerate(annot_list):
                    annot_obj = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
                    if not isinstance(annot_obj, dict):
                        continue
                    is_sig = annot_obj.get("/FT") == "/Sig"
                    if not is_sig and annot_obj.get("/Subtype") == "/Widget":
                        parent = annot_obj.get("/Parent")
                        if parent:
                            p = parent.get_object() if hasattr(parent, "get_object") else parent
                            if isinstance(p, dict) and p.get("/FT") == "/Sig":
                                is_sig = True
                    if is_sig:
                        sig_indices.append(i)
                for i in reversed(sig_indices):
                    del annot_list[i]
            except Exception:
                pass

        if page_idx in target_stamps:
            pw = float(page.mediabox.width)
            ph = float(page.mediabox.height)
            rect, page_rot, widget_meta = target_stamps[page_idx]

            # Prefer exact metadata from widget /V on the page if available
            signer_name = widget_meta.get("name") or base_signer_name
            signing_time = widget_meta.get("date") or base_signing_time
            sig_reason = widget_meta.get("reason") or base_reason
            sig_location = widget_meta.get("location") or base_location

            stamp_pdf_bytes = create_green_tick_stamp(
                page_width=pw,
                page_height=ph,
                rect=rect,
                signer_name=signer_name,
                signing_time=signing_time,
                original_sha256=original_sha256,
                reason=sig_reason,
                location=sig_location,
                page_rotation=page_rot
            )

            stamp_reader = pypdf.PdfReader(io.BytesIO(stamp_pdf_bytes))
            overlay_page = stamp_reader.pages[0]
            page.merge_page(overlay_page)

        writer.add_page(page)

    # Remove the AcroForm/signature fields so PDF viewers don't flag this display copy
    # as tampered: the green tick overlay changes the byte content, breaking every
    # original ByteRange hash. The cryptographic validation already happened; this
    # file is a visual record only, not a re-signable document.
    try:
        if "/AcroForm" in writer._root_object:
            del writer._root_object["/AcroForm"]
    except Exception:
        pass

    # Set Display Copy Metadata
    writer.add_metadata({
        "/Title": f"[Verified Copy] {validation_report.get('filename', 'document.pdf')}",
        "/Subject": "Cryptographically Verified Display Copy (Green Tick)",
        "/Creator": "Lab PDF Signature Sentinel",
        "/Producer": "Lab PDF Signature Sentinel Display Copy Engine",
        "/Keywords": "Verified, Digital Signature, Green Tick, Intact, PAdES, CCA India"
    })

    out_stream = io.BytesIO()
    writer.write(out_stream)
    return out_stream.getvalue()
