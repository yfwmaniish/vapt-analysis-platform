"""Report generation models."""

from __future__ import annotations

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class ReportFormat(str, Enum):
    HTML = "html"
    PDF = "pdf"


class ReportRequest(BaseModel):
    scan_id: str = Field(..., description="ID of the scan to generate report for")
    format: ReportFormat = Field(default=ReportFormat.HTML, description="Output format")
    include_ai_analysis: bool = Field(default=True, description="Include AI analysis in report")
