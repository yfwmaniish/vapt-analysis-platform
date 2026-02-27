"""
VAPTx — AI-Powered VAPT Security Platform

Main FastAPI application entry point.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from engine import config
from engine.api.router import api_router
from engine.utils.logger import get_logger

# ── Import scanners to trigger registration ────────────────────
import engine.scanners.port_scanner     # noqa: F401
import engine.scanners.ssl_scanner      # noqa: F401
import engine.scanners.subdomain_scanner  # noqa: F401
import engine.scanners.s3_scanner       # noqa: F401
import engine.scanners.ftp_scanner      # noqa: F401
import engine.scanners.jwt_scanner      # noqa: F401
import engine.scanners.header_scanner   # noqa: F401
import engine.scanners.cookie_scanner   # noqa: F401
import engine.scanners.dir_scanner      # noqa: F401
import engine.scanners.endpoint_scanner # noqa: F401
import engine.scanners.dorking_scanner  # noqa: F401
import engine.scanners.crawler_scanner  # noqa: F401
import engine.scanners.fuzzer_scanner   # noqa: F401
import engine.scanners.browser_scanner  # noqa: F401
import engine.scanners.ssrf_scanner     # noqa: F401
import engine.scanners.xxe_scanner      # noqa: F401
import engine.scanners.session_scanner     # noqa: F401
import engine.scanners.fingerprint_scanner # noqa: F401
import engine.scanners.cors_scanner        # noqa: F401
import engine.scanners.redirect_scanner    # noqa: F401

from engine.scanners.registry import ScannerRegistry

logger = get_logger("main")

app = FastAPI(
    title=config.PROJECT_NAME,
    description=config.PROJECT_DESCRIPTION,
    version=config.PROJECT_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ──────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ────────────────────────────────────────────────────
app.include_router(api_router)


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "engine": config.PROJECT_NAME,
        "version": config.PROJECT_VERSION,
        "scanners_loaded": len(ScannerRegistry.get_names()),
        "ai_available": bool(config.LLM_API_KEY),
    }


@app.on_event("startup")
async def startup_event():
    scanner_names = ScannerRegistry.get_names()
    logger.info(f"🚀 {config.PROJECT_NAME} v{config.PROJECT_VERSION} started")
    logger.info(f"📡 Loaded {len(scanner_names)} scanner modules: {', '.join(scanner_names)}")
    logger.info(f"🤖 AI Analysis: {'Enabled' if config.LLM_API_KEY else 'Disabled (no API key)'}")
    logger.info(f"🌐 CORS Origins: {config.CORS_ORIGINS}")
