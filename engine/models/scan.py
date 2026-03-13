"""Scan request/response models for the API layer."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanModule(str, Enum):
    """All available scanner modules."""
    PORT_SCAN = "port_scan"
    SSL_SCAN = "ssl_scan"
    SUBDOMAIN = "subdomain"
    S3_BUCKET = "s3_bucket"
    FTP = "ftp"
    JWT = "jwt"
    HEADERS = "headers"
    COOKIES = "cookies"
    DIR_BRUTEFORCE = "dir_bruteforce"
    ENDPOINTS = "endpoints"
    DORKING = "dorking"
    CRAWLER = "crawler"
    FUZZER = "fuzzer"
    BROWSER = "browser"
    SSRF = "ssrf"
    XXE = "xxe"
    SESSION = "session"
    FINGERPRINT = "fingerprint"
    CORS = "cors"
    REDIRECT = "redirect"
    VORTEX = "vortex"

class ScanRequest(BaseModel):
    target: str = Field(..., description="Target domain, IP, or URL to scan")
    modules: List[ScanModule] = Field(
        default=[m for m in ScanModule],
        description="Scanner modules to run. Defaults to all.",
    )
    jwt_token: Optional[str] = Field(None, description="JWT token for JWT analysis")
    auth_header: Optional[str] = Field(None, description="Global Authorization header (e.g., 'Bearer token') for authenticated scanning")
    vortex_categories: Optional[List[str]] = Field(None, description="Vulnerability categories for Vortex deep scanner (e.g., 'SQL Injection', 'XSS Injection')")
    timeout: int = Field(default=10, ge=1, le=120, description="Timeout per request in seconds")
    threads: int = Field(default=50, ge=1, le=200, description="Max concurrent threads")
    ai_analysis: bool = Field(default=True, description="Enable AI-powered vulnerability analysis")


class ScanResponse(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: ScanStatus = ScanStatus.PENDING
    target: str = ""
    modules: List[str] = []
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
    )
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0


class ScanResult(BaseModel):
    """Full scan result with all findings and attack surface mapping."""
    scan_id: str
    status: ScanStatus
    target: str
    modules_run: List[str] = []
    created_at: str = ""
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    findings: list = Field(default_factory=list)
    ai_summary: Optional[str] = None
    attack_surface: Optional[dict] = None
