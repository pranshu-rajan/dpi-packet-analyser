import re
import json
import struct
import shutil
import uuid
import asyncio
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.config import UPLOADS_DIR, OUTPUTS_DIR, SAMPLE_PCAP_PATH
from app.database import get_db
from app.models.db_models import CaptureRecord, ThreatEventModel
from app.models.schemas import AnalysisResponse, FilterRule, CaptureHistoryItem
from app.services.dpi_runner import DPIRunnerService, ANALYSIS_CACHE

router = APIRouter(prefix="/api/analyze", tags=["Analysis"])

MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
VALID_PCAP_MAGICS = {0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1}

def persist_analysis_to_db(result: AnalysisResponse, db: Session):
    """
    Saves or updates network capture telemetry and threat detections into PostgreSQL/Database.
    """
    try:
        rec = db.query(CaptureRecord).filter(CaptureRecord.id == result.analysis_id).first()
        if not rec:
            rec = CaptureRecord(
                id=result.analysis_id,
                filename=result.filename,
                file_size_bytes=result.file_size_bytes,
                total_packets=result.summary.total_packets,
                processed_packets=result.summary.forwarded,
                dropped_packets=result.summary.dropped,
                protocol_distribution=[app.model_dump() for app in result.applications],
                top_domains=[sni.model_dump() for sni in result.detected_snis],
                summary_metrics=result.summary.model_dump(),
                status="completed"
            )
            db.add(rec)
        else:
            rec.total_packets = result.summary.total_packets
            rec.processed_packets = result.summary.forwarded
            rec.dropped_packets = result.summary.dropped
            rec.protocol_distribution = [app.model_dump() for app in result.applications]
            rec.top_domains = [sni.model_dump() for sni in result.detected_snis]
            rec.summary_metrics = result.summary.model_dump()

        if result.threat_indicators:
            for ti in result.threat_indicators:
                threat = ThreatEventModel(
                    capture_id=result.analysis_id,
                    severity=ti.severity,
                    threat_type=ti.category,
                    details=f"{ti.title}: {ti.description}"
                )
                db.add(threat)

        db.commit()
    except Exception as e:
        db.rollback()
        print(f"Warning: Failed to persist capture session to DB: {e}")

@router.get("/status")
def get_status():
    return DPIRunnerService.get_engine_status()

@router.get("/history", response_model=List[CaptureHistoryItem])
def get_capture_history(db: Session = Depends(get_db)):
    """
    Returns list of all historical packet capture analyses saved in the database.
    """
    records = db.query(CaptureRecord).order_by(CaptureRecord.created_at.desc()).all()
    history = []
    for r in records:
        history.append(CaptureHistoryItem(
            id=r.id,
            filename=r.filename,
            file_size_bytes=r.file_size_bytes or 0,
            total_packets=r.total_packets or 0,
            processed_packets=r.processed_packets or 0,
            dropped_packets=r.dropped_packets or 0,
            duration_ms=r.duration_ms or 0.0,
            throughput_mbps=r.throughput_mbps or 0.0,
            status=r.status or "completed",
            created_at=r.created_at.isoformat() if r.created_at else ""
        ))
    return history

@router.get("/session/{analysis_id}", response_model=AnalysisResponse)
def get_analysis_session(analysis_id: str, db: Session = Depends(get_db)):
    """
    Retrieves analysis details for a specific historical session.
    """
    cached = ANALYSIS_CACHE.get(analysis_id)
    if cached and "response" in cached:
        return AnalysisResponse(**cached["response"])

    rec = db.query(CaptureRecord).filter(CaptureRecord.id == analysis_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Capture session not found in database.")

    # Reconstruct AnalysisResponse from database record
    summary_data = rec.summary_metrics or {
        "total_packets": rec.total_packets,
        "total_bytes": rec.file_size_bytes,
        "tcp_packets": 0,
        "udp_packets": 0,
        "forwarded": rec.processed_packets,
        "dropped": rec.dropped_packets
    }

    return AnalysisResponse(
        analysis_id=rec.id,
        filename=rec.filename,
        file_size_bytes=rec.file_size_bytes,
        timestamp=rec.created_at.strftime("%Y-%m-%d %H:%M:%S") if rec.created_at else "",
        summary=summary_data,
        thread_stats={"lbs": [], "fps": []},
        applications=rec.protocol_distribution or [],
        detected_snis=rec.top_domains or [],
        threat_score=0,
        threat_indicators=[],
        active_rules=[],
        output_pcap_name=f"{rec.id}_filtered.pcap",
        output_pcap_download_url=f"/api/analyze/download/{rec.id}_filtered.pcap"
    )

@router.delete("/session/{analysis_id}")
def delete_capture_session(analysis_id: str, db: Session = Depends(get_db)):
    """
    Deletes a capture session and its associated logs from the database.
    """
    rec = db.query(CaptureRecord).filter(CaptureRecord.id == analysis_id).first()
    if not rec:
        raise HTTPException(status_code=404, detail="Capture session not found.")

    db.delete(rec)
    db.commit()

    if analysis_id in ANALYSIS_CACHE:
        del ANALYSIS_CACHE[analysis_id]

    return {"status": "success", "deleted_session_id": analysis_id}

@router.post("/sample", response_model=AnalysisResponse)
async def analyze_sample(rules_json: Optional[str] = Form(None), db: Session = Depends(get_db)):
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
        result = await asyncio.to_thread(
            DPIRunnerService.run_engine,
            input_pcap=SAMPLE_PCAP_PATH,
            rules=rules,
            custom_id="sample_live"
        )
        persist_analysis_to_db(result, db)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/upload", response_model=AnalysisResponse)
async def upload_and_analyze(
    file: UploadFile = File(...),
    rules_json: Optional[str] = Form(None),
    db: Session = Depends(get_db)
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
        result = await asyncio.to_thread(
            DPIRunnerService.run_engine,
            input_pcap=dest_path,
            rules=rules,
            custom_id=file_id
        )
        persist_analysis_to_db(result, db)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/refilter", response_model=AnalysisResponse)
async def refilter_capture(
    analysis_id: str = Form(...),
    rules_json: str = Form(...),
    db: Session = Depends(get_db)
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
        result = await asyncio.to_thread(
            DPIRunnerService.run_engine,
            input_pcap=input_path,
            rules=rules,
            custom_id=analysis_id
        )
        persist_analysis_to_db(result, db)
        return result
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
async def get_latest_analysis(db: Session = Depends(get_db)):
    """
    Returns the most recent analysis from cache or executes sample if empty.
    """
    if ANALYSIS_CACHE:
        latest_key = list(ANALYSIS_CACHE.keys())[-1]
        return AnalysisResponse(**ANALYSIS_CACHE[latest_key]["response"])
    return await analyze_sample(db=db)
