"""Main API router that aggregates all endpoint modules."""

from __future__ import annotations

from fastapi import APIRouter

from engine.api.scans import router as scans_router
from engine.api.scans import vortex_router
from engine.api.websocket import router as ws_router

api_router = APIRouter()
api_router.include_router(scans_router)
api_router.include_router(vortex_router)
api_router.include_router(ws_router)
