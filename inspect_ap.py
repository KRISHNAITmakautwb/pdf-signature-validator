import pypdf
import io
import re

# Let's inspect test_verified_green_tick.pdf or create a test signed PDF and inspect its /AP
from app.sample_generator import create_sample_signed_pdf

pdf_bytes = create_sample_signed_pdf()
reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
p = reader.pages[0]
annots = p.get("/Annots")
if annots:
    for a in annots:
        obj = a.get_object()
        print("Annot keys:", list(obj.keys()))
        ap = obj.get("/AP")
        if ap:
            ap_obj = ap.get_object()
            print("AP keys:", list(ap_obj.keys()))
            n = ap_obj.get("/N")
            if n:
                n_obj = n.get_object()
                print("N type:", type(n_obj))
                if hasattr(n_obj, "get_data"):
                    data = n_obj.get_data().decode('latin1', errors='ignore')
                    print("N stream data sample:\n", data[:400])
                if hasattr(n_obj, "get"):
                    res = n_obj.get("/Resources")
                    if res:
                        print("N Resources:", list(res.get_object().keys()))
