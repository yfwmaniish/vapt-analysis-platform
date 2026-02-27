"""
Scan API endpoints.

Handles scan creation, status checking, and result retrieval.
"""

from __future__ import annotations

import uuid
import asyncio
from typing import Dict

from fastapi import APIRouter, HTTPException, BackgroundTasks, Response

from engine.models.scan import ScanRequest, ScanResponse, ScanResult, ScanStatus, ScanModule
from engine.agents.orchestrator import ScanOrchestrator
from engine.scanners.registry import ScannerRegistry
from engine.reports.generator import ReportGenerator
from engine.utils.logger import get_logger

logger = get_logger("api.scans")

router = APIRouter(prefix="/api/scans", tags=["Scans"])

# In-memory scan store (production would use a database)
_scans: Dict[str, ScanResult] = {}
_scan_progress: Dict[str, list] = {}


def _progress_handler(scan_id: str):
    """Create a progress handler that stores events for a scan."""
    def handler(module: str, pct: float, msg: str):
        if scan_id not in _scan_progress:
            _scan_progress[scan_id] = []
        _scan_progress[scan_id].append({
            "module": module,
            "percentage": pct,
            "message": msg,
        })
    return handler


async def _run_scan_task(scan_id: str, request: ScanRequest):
    """Background task that runs the actual scan."""
    orchestrator = ScanOrchestrator()
    orchestrator.set_progress_handler(_progress_handler(scan_id))

    try:
        result = await orchestrator.run_scan(
            scan_id=scan_id,
            target=request.target,
            modules=request.modules,
            timeout=request.timeout,
            threads=request.threads,
            ai_analysis=request.ai_analysis,
            jwt_token=request.jwt_token or "",
            auth_header=request.auth_header or "",
        )
        _scans[scan_id] = result
    except Exception as exc:
        logger.error(f"Scan {scan_id[:8]} failed: {exc}")
        _scans[scan_id] = ScanResult(
            scan_id=scan_id,
            status=ScanStatus.FAILED,
            target=request.target,
        )


@router.post("", response_model=ScanResponse)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new security scan."""
    scan_id = str(uuid.uuid4())

    # Initialize scan in store
    _scans[scan_id] = ScanResult(
        scan_id=scan_id,
        status=ScanStatus.RUNNING,
        target=request.target,
        modules_run=[m.value for m in request.modules],
    )
    _scan_progress[scan_id] = []

    # Run scan in background
    background_tasks.add_task(_run_scan_task, scan_id, request)

    logger.info(f"Scan {scan_id[:8]} created for {request.target}")

    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.RUNNING,
        target=request.target,
        modules=[m.value for m in request.modules],
    )


@router.get("", response_model=list)
async def list_scans():
    """List all scans."""
    scans = []
    for scan_id, result in _scans.items():
        # Count severities
        critical = sum(1 for f in result.findings if f.get("severity") == "critical")
        high = sum(1 for f in result.findings if f.get("severity") == "high")
        scans.append({
            "scan_id": result.scan_id,
            "target": result.target,
            "status": result.status,
            "created_at": result.created_at,
            "completed_at": result.completed_at,
            "duration_seconds": result.duration_seconds,
            "findings_count": len(result.findings),
            "critical_count": critical,
            "high_count": high,
        })
    return sorted(scans, key=lambda s: s.get("created_at", ""), reverse=True)


@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    """Get full scan results."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = _scans[scan_id]
    return result.model_dump()


@router.get("/{scan_id}/report")
async def download_scan_report(scan_id: str):
    """Download the professional HTML report for a scan."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = _scans[scan_id]
    if result.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan must be completed to generate a report")

    generator = ReportGenerator()
    html_content = generator.generate_html(result.model_dump())

    return Response(
        content=html_content,
        media_type="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="Veltro_VAPT_Report_{scan_id[:8]}.html"'
        }
    )


@router.get("/{scan_id}/progress")
async def get_scan_progress(scan_id: str):
    """Get scan progress events."""
    if scan_id not in _scans:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan_id,
        "status": _scans[scan_id].status,
        "events": _scan_progress.get(scan_id, []),
    }


@router.get("/scanners/available")
async def list_scanners():
    """List all available scanner modules."""
    return ScannerRegistry.get_info()
