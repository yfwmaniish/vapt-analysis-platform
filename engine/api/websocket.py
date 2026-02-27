"""
WebSocket endpoint for real-time scan progress streaming.
"""

from __future__ import annotations

import asyncio
import json
from typing import Dict, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from engine.utils.logger import get_logger

logger = get_logger("api.websocket")

router = APIRouter(tags=["WebSocket"])

# Active WebSocket connections per scan_id
_connections: Dict[str, Set[WebSocket]] = {}


async def broadcast_progress(scan_id: str, data: dict):
    """Broadcast a progress update to all connected clients for a scan."""
    if scan_id in _connections:
        message = json.dumps(data)
        dead_connections = set()
        for ws in _connections[scan_id]:
            try:
                await ws.send_text(message)
            except Exception:
                dead_connections.add(ws)
        # Clean up dead connections
        _connections[scan_id] -= dead_connections


@router.websocket("/api/ws/scan/{scan_id}")
async def scan_progress_ws(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint for streaming live scan progress.

    Clients connect to receive real-time updates as each scanner
    module reports progress.
    """
    await websocket.accept()

    # Register connection
    if scan_id not in _connections:
        _connections[scan_id] = set()
    _connections[scan_id].add(websocket)

    logger.info(f"WebSocket client connected for scan {scan_id[:8]}")

    try:
        # Keep connection alive and poll for progress
        from engine.api.scans import _scans, _scan_progress

        last_event_idx = 0

        while True:
            await asyncio.sleep(0.5)  # Poll every 500ms

            # Send new progress events
            events = _scan_progress.get(scan_id, [])
            if len(events) > last_event_idx:
                new_events = events[last_event_idx:]
                last_event_idx = len(events)
                for event in new_events:
                    await websocket.send_json({
                        "type": "progress",
                        "scan_id": scan_id,
                        **event,
                    })

            # Check if scan is complete
            scan = _scans.get(scan_id)
            if scan and scan.status in ("completed", "failed", "cancelled"):
                await websocket.send_json({
                    "type": "complete",
                    "scan_id": scan_id,
                    "status": scan.status,
                    "findings_count": len(scan.findings),
                })
                break

    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected from scan {scan_id[:8]}")
    except Exception as exc:
        logger.error(f"WebSocket error: {exc}")
    finally:
        if scan_id in _connections:
            _connections[scan_id].discard(websocket)
            if not _connections[scan_id]:
                del _connections[scan_id]
