import os
import io
import shutil
import asyncio
from typing import List, Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.responses import JSONResponse, Response, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.validator import PDFSignatureValidator, PYHANKO_AVAILABLE, CRYPTO_AVAILABLE
from app.sample_generator import create_sample_signed_pdf, create_sample_tampered_pdf, create_minimal_pdf
from app.display_copy_generator import generate_verified_display_copy

CERTS_DIR = os.getenv("CERTS_DIR", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "certs")))
os.makedirs(CERTS_DIR, exist_ok=True)

app = FastAPI(
    title="Lab PDF Digital Signature Sentinel",
    description="High-assurance digital signature validation service for research labs. Supports PAdES, ISO 32000, CMS/PKCS#7, shadow attack inspection, and certificate trust chain analysis.",
    version="1.0.0"
)

# Enable CORS for lab network / microservices
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

validator = PDFSignatureValidator(trust_roots_dir=CERTS_DIR)


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Lab PDF Signature Validation Service",
        "pyhanko_available": PYHANKO_AVAILABLE,
        "cryptography_available": CRYPTO_AVAILABLE,
        "custom_trust_roots_count": len(validator.custom_root_certs)
    }


@app.post("/api/validate")
async def validate_single_pdf(file: UploadFile = File(...)):
    """
    Validates the digital signatures and integrity of an uploaded PDF document.
    """
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Uploaded file must be a PDF document (.pdf)")

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded PDF file is empty.")

    try:
        report = await asyncio.to_thread(validator.validate, content, file.filename)
        return JSONResponse(content={"success": True, "report": report})
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": str(e), "filename": file.filename}
        )


@app.post("/api/verified-copy")
async def download_verified_display_copy(file: UploadFile = File(...)):
    """
    Validates the uploaded PDF and, if cryptographically intact, generates a
    'Verified Display Copy' with a permanent Green Checkmark (✔).
    This replaces the yellow '?' with the official green tick mark visible in all viewers.
    """
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Uploaded file must be a PDF document (.pdf)")

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded PDF file is empty.")

    try:
        report = await asyncio.to_thread(validator.validate, content, file.filename)
        if not report.get("is_signed"):
            raise HTTPException(status_code=400, detail="Document does not contain any digital signatures.")

        if report.get("overall_status") == "TAMPERED_OR_INVALID":
            raise HTTPException(
                status_code=400,
                detail="Security rejection: Cannot generate verified display copy for a document with invalid or tampered signatures."
            )

        verified_bytes = await asyncio.to_thread(generate_verified_display_copy, content, report)
        
        base_name = os.path.splitext(file.filename)[0]
        out_filename = f"{base_name}_verified_green_tick.pdf"
        
        return Response(
            content=verified_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{out_filename}"',
                "Access-Control-Expose-Headers": "Content-Disposition"
            }
        )
    except HTTPException:
        raise
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate verified copy: {str(e)}")


@app.post("/api/batch-validate")
async def validate_batch_pdfs(files: List[UploadFile] = File(...)):
    """
    Validates multiple PDF documents in a single request.
    """
    results = []
    for file in files:
        if not file.filename.lower().endswith(".pdf"):
            results.append({
                "filename": file.filename,
                "error": "Not a PDF file",
                "overall_status": "SKIPPED"
            })
            continue

        content = await file.read()
        try:
            report = await asyncio.to_thread(validator.validate, content, file.filename)
            results.append(report)
        except Exception as e:
            results.append({
                "filename": file.filename,
                "error": str(e),
                "overall_status": "ERROR"
            })

    return {"success": True, "count": len(results), "reports": results}


@app.get("/api/samples/valid")
async def get_sample_valid():
    """Generates and downloads a valid test digitally signed PDF."""
    try:
        # run in thread because pyHanko's sign_pdf uses asyncio.run() internally
        pdf_bytes = await asyncio.to_thread(create_sample_signed_pdf)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=valid_signed_sample.pdf"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate valid sample: {str(e)}")


@app.get("/api/samples/tampered")
async def get_sample_tampered():
    """Generates and downloads an intentionally tampered signed PDF (demonstrates signature invalidation)."""
    try:
        pdf_bytes = await asyncio.to_thread(create_sample_tampered_pdf)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=tampered_signed_sample.pdf"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate tampered sample: {str(e)}")


@app.get("/api/samples/unsigned")
async def get_sample_unsigned():
    """Generates and downloads a regular unsigned PDF."""
    pdf_bytes = create_minimal_pdf("Unsigned Research Note", "This document has not been digitally signed.")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=unsigned_sample.pdf"}
    )


@app.get("/api/trusted-certs")
async def list_trusted_certs():
    """Lists trusted custom Root CAs stored in the service."""
    certs = []
    if os.path.exists(CERTS_DIR):
        for fname in os.listdir(CERTS_DIR):
            if fname.endswith(('.crt', '.pem', '.cer')):
                fpath = os.path.join(CERTS_DIR, fname)
                certs.append({
                    "filename": fname,
                    "size_bytes": os.path.getsize(fpath)
                })
    return {"trusted_certs": certs, "certs_dir": CERTS_DIR}


@app.post("/api/trusted-certs")
async def upload_trusted_cert(file: UploadFile = File(...)):
    """Uploads a lab root CA or intermediate certificate (.pem, .crt) into the trust store."""
    if not (file.filename.endswith('.pem') or file.filename.endswith('.crt') or file.filename.endswith('.cer')):
        raise HTTPException(status_code=400, detail="Certificate must have .pem, .crt, or .cer extension")

    target_path = os.path.join(CERTS_DIR, os.path.basename(file.filename))
    with open(target_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Reload validator roots
    validator.custom_root_certs = validator._load_custom_roots()

    return {
        "success": True,
        "message": f"Certificate '{file.filename}' added to lab trust store.",
        "active_roots_count": len(validator.custom_root_certs)
    }


# Mount web frontend
STATIC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "static"))
os.makedirs(STATIC_DIR, exist_ok=True)

@app.get("/")
async def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "PDF Signature Validator API running. Visit /docs for Swagger API."}

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
