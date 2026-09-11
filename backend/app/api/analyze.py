import re
import json
import struct
import shutil
import uuid
import asyncio
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse

from app.config import UPLOADS_DIR, OUTPUTS_DIR, SAMPLE_PCAP_PATH
from app.models.schemas import AnalysisResponse, FilterRule
from app.services.dpi_runner import DPIRunnerService, ANALYSIS_CACHE

router = APIRouter(prefix="/api/analyze", tags=["Analysis"])

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
VALID_PCAP_MAGICS = {0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1}

@router.get("/status")
def get_status():
    return DPIRunnerService.get_engine_status()

@router.post("/sample", response_model=AnalysisResponse)
async def analyze_sample(rules_json: Optional[str] = Form(None)):
    """
    Executes DPI Engine on the built-in test_dpi.pcap capture.
    """
    if not SAMPLE_PCAP_PATH.exists():
        raise HTTPException(status_code=404, detail="Sample PCAP file not found.")

    rules: List[FilterRule] = []
    if rules_json:
        try:
            raw_rules = json.loads(rules_json)
            rules = [FilterRule(**r) for r in raw_rules]
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid rules JSON: {str(e)}")

    try:
        return await asyncio.to_thread(
            DPIRunnerService.run_engine,
            input_pcap=SAMPLE_PCAP_PATH,
            rules=rules,
            custom_id="sample_live"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/upload", response_model=AnalysisResponse)
async def upload_and_analyze(
    file: UploadFile = File(...),
    rules_json: Optional[str] = Form(None)
):
    """
    Uploads a custom .pcap / .cap file and executes DPI inspection with size and magic validation.
    """
    if not file.filename or not file.filename.lower().endswith((".pcap", ".cap")):
        raise HTTPException(status_code=400, detail="Only standard .pcap and .cap files are supported.")

    # Sanitize filename against path traversal
    raw_name = Path(file.filename).name
    safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', raw_name)
    file_id = str(uuid.uuid4())[:8]
    dest_path = UPLOADS_DIR / f"{file_id}_{safe_name}"

    # Read first 24 bytes to validate magic header before storing
    header_bytes = await file.read(24)
    if len(header_bytes) < 24:
        raise HTTPException(status_code=400, detail="Invalid PCAP file: file is truncated (under 24 bytes).")

    magic = struct.unpack("<I", header_bytes[:4])[0]
    if magic not in VALID_PCAP_MAGICS:
        raise HTTPException(status_code=400, detail="Invalid PCAP file: unrecognized magic header.")

    # Write file in chunks and enforce size limit
    total_bytes = len(header_bytes)
    with open(dest_path, "wb") as buffer:
        buffer.write(header_bytes)
        while chunk := await file.read(1024 * 1024):  # 1MB chunks
            total_bytes += len(chunk)
            if total_bytes > MAX_UPLOAD_SIZE:
                buffer.close()
                dest_path.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="File too large (exceeds 50MB limit).")
            buffer.write(chunk)

    rules: List[FilterRule] = []
    if rules_json:
        try:
            raw_rules = json.loads(rules_json)
            rules = [FilterRule(**r) for r in raw_rules]
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid rules JSON: {str(e)}")

    try:
        return await asyncio.to_thread(
            DPIRunnerService.run_engine,
            input_pcap=dest_path,
            rules=rules,
            custom_id=file_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/refilter", response_model=AnalysisResponse)
async def refilter_capture(
    analysis_id: str = Form(...),
    rules_json: str = Form(...)
):
    """
    Re-filters an already loaded capture using updated firewall rules.
    """
    cached = ANALYSIS_CACHE.get(analysis_id)
    if not cached:
        # Check if it was sample_live
        if analysis_id == "sample_live" and SAMPLE_PCAP_PATH.exists():
            input_path = SAMPLE_PCAP_PATH
        else:
            raise HTTPException(status_code=404, detail="Analysis session not found. Please re-upload PCAP.")
    else:
        input_path = Path(cached["input_pcap"])

    rules: List[FilterRule] = []
    try:
        raw_rules = json.loads(rules_json)
        rules = [FilterRule(**r) for r in raw_rules]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid rules JSON: {str(e)}")

    try:
        return await asyncio.to_thread(
            DPIRunnerService.run_engine,
            input_pcap=input_path,
            rules=rules,
            custom_id=analysis_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/download/{filename}")
def download_filtered_pcap(filename: str):
    """
    Downloads the filtered PCAP generated by the DPI engine with path traversal defense.
    """
    safe_name = Path(filename).name
    file_path = (OUTPUTS_DIR / safe_name).resolve()
    
    # Path traversal validation
    if not file_path.is_relative_to(OUTPUTS_DIR.resolve()) or not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found or access denied.")

    return FileResponse(
        path=str(file_path),
        filename=safe_name,
        media_type="application/vnd.tcpdump.pcap"
    )

@router.get("/latest", response_model=AnalysisResponse)
async def get_latest_analysis():
    """
    Returns the most recent analysis from cache or executes sample if empty.
    """
    if ANALYSIS_CACHE:
        latest_key = list(ANALYSIS_CACHE.keys())[-1]
        return AnalysisResponse(**ANALYSIS_CACHE[latest_key]["response"])
    return await analyze_sample()
