"""
api.py
─────────────────────────────────────────────────────────────────────────────
Thin FastAPI layer over pipeline_core.py. This is the piece the React UI
actually talks to over HTTP — it does no watermarking logic itself, it just:
  1. loads .env (must happen BEFORE importing pipeline_core, since that
     module derives its crypto secrets from WATERMARK_PASSPHRASE at import
     time),
  2. accepts uploaded image files and decodes them into the BGR numpy
     arrays pipeline_core's functions expect,
  3. calls register_image() / gateway_check() / recover_case() / load_results(),
  4. serves back the signed image / tamper heatmap / recovered original as
     downloadable files.

Run from inside backend/ (so the relative "yolov8n-seg.pt" path and the
OUTPUT_DIR-relative files resolve correctly):

    cd backend
    pip install -r requirements.txt
    uvicorn api:app --reload --port 8000
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# Must run before "import pipeline_core" — that module reads
# WATERMARK_PASSPHRASE / PINATA_JWT / WATERMARK_OUTPUT_DIR as soon as it is
# imported (see its _load_or_create_secrets() call at module scope).
load_dotenv()

import numpy as np
import cv2
from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

import pipeline_core as core

app = FastAPI(title="Zero-Watermark API")

# ── CORS ─────────────────────────────────────────────────────────────────
# Vite's default dev server is http://localhost:5173. Add more origins via
# the CORS_ORIGINS env var (comma-separated) if you deploy the frontend
# somewhere else.
_default_origins = ["http://localhost:5173", "http://127.0.0.1:5173"]
_extra_origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_default_origins + _extra_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── helpers ──────────────────────────────────────────────────────────────
def _read_upload_as_bgr(upload: UploadFile) -> np.ndarray:
    data = upload.file.read()
    if not data:
        raise HTTPException(400, "Empty file upload")
    arr = np.frombuffer(data, dtype=np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        raise HTTPException(400, f"Could not decode image: {upload.filename}")
    return img


def _safe_name(name: str) -> str:
    # prevent path traversal on the download endpoints below
    return os.path.basename(name)


# ── routes ───────────────────────────────────────────────────────────────
@app.get("/api/health")
def health():
    return {"ok": True}


@app.get("/api/platforms")
def platforms():
    """So the frontend doesn't have to hardcode thresholds/labels."""
    return core.PLATFORMS


@app.post("/api/register")
def register(file: UploadFile = File(...)):
    img_bgr = _read_upload_as_bgr(file)
    try:
        result = core.register_image(img_bgr, filename=file.filename)
    except Exception as e:
        raise HTTPException(500, f"Registration failed: {e}")
    return JSONResponse(result)


@app.post("/api/gateway-check")
def gateway_check(file: UploadFile = File(...), platform: str = Form(...)):
    if platform not in core.PLATFORMS:
        raise HTTPException(400, f"Unknown platform '{platform}'. Choose from {list(core.PLATFORMS)}")
    img_bgr = _read_upload_as_bgr(file)
    try:
        result = core.gateway_check(img_bgr, filename=file.filename, platform=platform)
    except Exception as e:
        raise HTTPException(500, f"Gateway check failed: {e}")
    return JSONResponse(result)


@app.post("/api/recover/{case_id}")
def recover(case_id: str):
    result = core.recover_case(case_id)
    if not result.get("ok"):
        raise HTTPException(404, result.get("reason", "recovery_failed"))
    return JSONResponse(result)


@app.get("/api/results")
def results():
    return JSONResponse(core.load_results())


# ── file downloads ───────────────────────────────────────────────────────
# register_image() writes the signed copy to OUTPUT_DIR; gateway_check()
# writes heatmaps to HEATMAP_DIR; recover_case() writes the delivered
# original to OUTPUT_DIR as well. Serve them by basename only.

@app.get("/api/download/signed/{name}")
def download_signed(name: str):
    path = Path(core.OUTPUT_DIR) / _safe_name(name)
    if not path.exists():
        raise HTTPException(404, "File not found")
    return FileResponse(path, filename=path.name)


@app.get("/api/download/heatmap/{name}")
def download_heatmap(name: str):
    path = Path(core.HEATMAP_DIR) / _safe_name(name)
    if not path.exists():
        raise HTTPException(404, "File not found")
    return FileResponse(path, filename=path.name)


@app.get("/api/download/delivery/{name}")
def download_delivery(name: str):
    path = Path(core.OUTPUT_DIR) / _safe_name(name)
    if not path.exists():
        raise HTTPException(404, "File not found")
    return FileResponse(path, filename=path.name)