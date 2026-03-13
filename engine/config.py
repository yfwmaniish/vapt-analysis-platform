"""
Central configuration for the VAPT Security Platform.

All environment variables and defaults are managed here.
The project name is a placeholder — rename it in one place.
"""

import os
from pathlib import Path

# ─── Project Metadata ───────────────────────────────────────────
PROJECT_NAME = "SecureSuiteX"
PROJECT_VERSION = "1.0.0"
PROJECT_DESCRIPTION = "AI-Powered VAPT Security Platform"

# ─── Paths ─────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
WORDLISTS_DIR = BASE_DIR / "wordlists"
REPORTS_DIR = BASE_DIR / "reports" / "output"

# ─── API Keys ──────────────────────────────────────────────────
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")  # Placeholder

# ─── LLM Configuration (OpenRouter) ───────────────────────────
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_API_BASE = os.getenv("LLM_API_BASE", "https://openrouter.ai/api/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "anthropic/claude-sonnet-4")

# ─── Scanner Defaults ─────────────────────────────────────────
DEFAULT_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "10"))
DEFAULT_THREADS = int(os.getenv("SCAN_THREADS", "50"))
DEFAULT_USER_AGENT = f"{PROJECT_NAME}/{PROJECT_VERSION}"

# ─── Docker Sandbox ───────────────────────────────────────────
DOCKER_ENABLED = os.getenv("DOCKER_ENABLED", "true").lower() == "true"
DOCKER_IMAGE = os.getenv("DOCKER_IMAGE", "securesuitex-sandbox:latest")

# ─── Server ───────────────────────────────────────────────────
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

# ─── S3 Bucket Scanning ──────────────────────────────────────
S3_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
    "ap-south-1", "ap-southeast-1", "ap-southeast-2",
    "ap-northeast-1", "ap-northeast-2", "sa-east-1",
]

S3_BUCKET_PATTERNS = [
    "{target}", "{target}-backup", "{target}-backups",
    "{target}-dev", "{target}-test", "{target}-staging",
    "{target}-prod", "{target}-production", "{target}-logs",
    "{target}-assets", "{target}-data", "{target}-files",
    "backup-{target}", "dev-{target}", "staging-{target}",
]

# ─── JWT Common Weak Secrets ─────────────────────────────────
JWT_COMMON_SECRETS = [
    "secret", "password", "123456", "admin", "root",
    "test", "key", "jwt", "token", "default", "changeme",
    "your-secret-key", "secretkey", "supersecret", "topsecret",
]

# ─── Risk Level Colors ───────────────────────────────────────
RISK_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
    "INFO": "#06b6d4",
}
