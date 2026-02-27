"""Finding and severity models for vulnerability results."""

from __future__ import annotations

from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """A single vulnerability or security finding."""
    scanner: str = Field(..., description="Scanner module that produced this finding")
    type: str = Field(..., description="Category of finding (e.g., Open Port, Weak SSL)")
    severity: Severity = Field(..., description="Risk severity level")
    title: str = Field(..., description="Short descriptive title")
    description: str = Field(..., description="Detailed explanation of the finding")
    evidence: Optional[str] = Field(None, description="Raw evidence or proof")
    location: Optional[str] = Field(None, description="Where the vulnerability was found")
    remediation: Optional[str] = Field(None, description="Suggested fix")
    cwe_id: Optional[str] = Field(None, description="CWE identifier if applicable")
    owasp_category: Optional[str] = Field(None, description="OWASP Top 10 2025 category (e.g., A03: Injection)")
    cvss_score: Optional[float] = Field(None, ge=0, le=10, description="CVSS score")
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    ai_analysis: Optional[str] = Field(None, description="AI-generated analysis")

    class Config:
        json_schema_extra = {
            "example": {
                "scanner": "ssl_scanner",
                "type": "Weak SSL Configuration",
                "severity": "high",
                "title": "TLS 1.0 Enabled",
                "description": "The server supports TLS 1.0 which has known vulnerabilities.",
                "evidence": "Supported: TLSv1.0",
                "location": "example.com:443",
                "remediation": "Disable TLS 1.0 and 1.1. Use TLS 1.2+ only.",
                "cwe_id": "CWE-326",
                "references": ["https://cwe.mitre.org/data/definitions/326.html"],
            }
        }
