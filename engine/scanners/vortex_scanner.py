"""
VortexScanner — Deep vulnerability scanner powered by the payload library.

Loads payload files from selected vulnerability categories (70+ available),
injects them into every discovered injectable point (URL params, form fields,
URL path segments), and detects vulnerabilities via category-specific
detection strategies.

This scanner is designed to run as a Phase 2 (attack) scanner, consuming
the attack_surface produced by the CrawlerScanner in Phase 1.

Verification Layer:
    Every initial detection is treated as a "candidate" and passed through
    the ResponseVerifier, which performs secondary confirmation requests:
      - Time-based: sends two requests with different delay values and
        checks that the response times are proportional.
      - Boolean: sends true-condition and false-condition variants and
        checks that the response lengths diverge predictably.
      - XSS context: injects a unique harmless probe tag and checks whether
        it is returned unescaped (vs. entity-encoded).
    Only verified candidates are promoted to reported Findings.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import aiohttp

from engine.models.finding import Finding
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.logger import get_logger

logger = get_logger("scanner.vortex")

# ── Constants ────────────────────────────────────────────────────────────────

PAYLOADS_DIR = Path(__file__).resolve().parents[2] / "payloads"

# Maximum payloads per category — stride-sampled for diversity
MAX_PAYLOADS_PER_CATEGORY = 100

# Maximum injectable points (params + forms) to test
MAX_INJECTABLE_POINTS = 20

# Concurrency limiter for HTTP requests
DEFAULT_CONCURRENCY = 80

# Worker pool batch size for progress reporting
MAX_BATCH_SIZE = 50

# Verification constants
VERIFY_TIME_SHORT = 2       # seconds — short sleep for time-based correlation
VERIFY_TIME_LONG = 4        # seconds — long sleep for time-based correlation
VERIFY_TIME_TOLERANCE = 0.8  # minimum ratio of measured vs expected delta
VERIFY_XSS_PROBE = "<v0rtex_probe>"       # unique harmless tag for XSS check
VERIFY_XSS_ENCODED = "&lt;v0rtex_probe&gt;"  # entity-encoded version

# Known sub-directories inside payload categories that hold .txt files
INTRUDER_DIRS = ("Intruders", "Intruder", "Files")


# ── Detection Strategies ─────────────────────────────────────────────────────

# SQL error patterns across major DBMS engines
SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"microsoft ole db provider for sql server",
    r"pg_query\(\).*error",
    r"supplied argument is not a valid (mysql|postgresql)",
    r"org\.postgresql\.util\.psqlexception",
    r"com\.microsoft\.sqlserver\.jdbc",
    r"oracle.*error",
    r"ora-\d{5}",
    r"db2 sql error",
    r"sqlite3?_",
    r"sql syntax.*error",
    r"invalid.*sql",
    r"syntax error at or near",
]

SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)

# NoSQL-specific payload markers (to distinguish from SQL)
NOSQL_PAYLOAD_MARKERS = [
    "$ne", "$gt", "$lt", "$eq", "$regex", "$where",
    "$exists", "$in", "$nin", "$or", "$and", "$not",
    ".find(", ".findOne(", ".aggregate(",
    "db.collection", "mapReduce",
]

# NoSQL error indicators in responses
NOSQL_ERROR_PATTERNS = [
    r"MongoError",
    r"mongo.*exception",
    r"bson.*error",
    r"Cannot apply \$",
    r"unrecognized expression",
    r"unknown operator",
    r"\$where not allowed",
    r"bad query",
]

NOSQL_ERROR_RE = re.compile("|".join(NOSQL_ERROR_PATTERNS), re.IGNORECASE)

# SSTI math canaries: payload contains e.g., {{7*7331}} or ${7*7331}
SSTI_CANARY_RESULT = "51317"  # 7 * 7331

# Command injection canaries
CMDI_CANARY = "v0rt3x_c4n4ry"

# XXE indicator patterns
XXE_INDICATORS = [
    "root:x:0:0",       # /etc/passwd content
    "[boot loader]",    # Windows boot.ini
]

# Directory traversal indicators
PATH_TRAVERSAL_INDICATORS = [
    "root:x:0:0",           # Unix /etc/passwd
    "[boot loader]",        # Windows boot.ini
    "[fonts]",              # Windows win.ini
    "\\WINDOWS\\system32",  # Windows path
]

# XSS tokens that must appear as complete attribute/tag openers, not substrings
XSS_EXECUTABLE_TOKENS = [
    "<script", "</script", "<img ", "<svg ", "<iframe ",
    "onerror=", "onload=", "onfocus=", "onmouseover=",
    "javascript:", "<body ",
]

# CWE/OWASP mapping per category
CATEGORY_META: Dict[str, Dict[str, Any]] = {
    "SQL Injection":                     {"cwe": "CWE-89",  "owasp": "A03: Injection",               "severity": "critical"},
    "NoSQL Injection":                   {"cwe": "CWE-943", "owasp": "A03: Injection",               "severity": "critical"},
    "XSS Injection":                     {"cwe": "CWE-79",  "owasp": "A03: Injection",               "severity": "high"},
    "Command Injection":                 {"cwe": "CWE-78",  "owasp": "A03: Injection",               "severity": "critical"},
    "Server Side Template Injection":    {"cwe": "CWE-1336","owasp": "A03: Injection",               "severity": "critical"},
    "Server Side Request Forgery":       {"cwe": "CWE-918", "owasp": "A10: SSRF",                    "severity": "high"},
    "XXE Injection":                     {"cwe": "CWE-611", "owasp": "A05: Security Misconfiguration","severity": "critical"},
    "Directory Traversal":               {"cwe": "CWE-22",  "owasp": "A01: Broken Access Control",   "severity": "high"},
    "Open Redirect":                     {"cwe": "CWE-601", "owasp": "A01: Broken Access Control",   "severity": "medium"},
    "CORS Misconfiguration":             {"cwe": "CWE-942", "owasp": "A05: Security Misconfiguration","severity": "medium"},
    "LDAP Injection":                    {"cwe": "CWE-90",  "owasp": "A03: Injection",               "severity": "critical"},
    "XPATH Injection":                   {"cwe": "CWE-643", "owasp": "A03: Injection",               "severity": "high"},
    "CSV Injection":                     {"cwe": "CWE-1236","owasp": "A03: Injection",               "severity": "medium"},
    "CRLF Injection":                    {"cwe": "CWE-93",  "owasp": "A03: Injection",               "severity": "medium"},
    "File Inclusion":                    {"cwe": "CWE-98",  "owasp": "A03: Injection",               "severity": "critical"},
    "Insecure Deserialization":          {"cwe": "CWE-502", "owasp": "A08: Software and Data Integrity Failures", "severity": "critical"},
    "HTTP Request Smuggling":            {"cwe": "CWE-444", "owasp": "A05: Security Misconfiguration","severity": "high"},
    "Type Juggling":                     {"cwe": "CWE-843", "owasp": "A03: Injection",               "severity": "medium"},
    "Race Condition":                    {"cwe": "CWE-362", "owasp": "A04: Insecure Design",         "severity": "medium"},
    "GraphQL Injection":                 {"cwe": "CWE-89",  "owasp": "A03: Injection",               "severity": "high"},
    "LaTeX Injection":                   {"cwe": "CWE-94",  "owasp": "A03: Injection",               "severity": "medium"},
    "XSLT Injection":                    {"cwe": "CWE-91",  "owasp": "A03: Injection",               "severity": "high"},
    "OAuth Misconfiguration":            {"cwe": "CWE-287", "owasp": "A07: Identification and Authentication Failures", "severity": "high"},
    "SAML Injection":                    {"cwe": "CWE-287", "owasp": "A07: Identification and Authentication Failures", "severity": "critical"},
    "Prototype Pollution":               {"cwe": "CWE-1321","owasp": "A03: Injection",               "severity": "high"},
    "HTTP Parameter Pollution":          {"cwe": "CWE-235", "owasp": "A03: Injection",               "severity": "medium"},
    "Mass Assignment":                   {"cwe": "CWE-915", "owasp": "A01: Broken Access Control",   "severity": "high"},
    "Insecure Direct Object References": {"cwe": "CWE-639", "owasp": "A01: Broken Access Control",   "severity": "high"},
    "JWT Vulnerabilities":               {"cwe": "CWE-347", "owasp": "A02: Cryptographic Failures",  "severity": "critical"},
    "Upload Insecure Files":             {"cwe": "CWE-434", "owasp": "A04: Insecure Design",         "severity": "critical"},
}

# Fallback metadata for categories not explicitly mapped
DEFAULT_META = {"cwe": "CWE-20", "owasp": "A03: Injection", "severity": "medium"}


# ── Payload Loader ────────────────────────────────────────────────────────────

class PayloadLoader:
    """Loads and caches payload files from the payloads/ directory tree."""

    _cache: Dict[str, List[str]] = {}

    @classmethod
    def discover_categories(cls) -> List[Dict[str, Any]]:
        """Return metadata about all available payload categories."""
        categories = []
        if not PAYLOADS_DIR.exists():
            logger.warning(f"Payloads directory not found: {PAYLOADS_DIR}")
            return categories

        for entry in sorted(PAYLOADS_DIR.iterdir()):
            if entry.is_dir() and not entry.name.startswith((".", "_")):
                payload_count = cls._count_payloads_in(entry)
                meta = CATEGORY_META.get(entry.name, DEFAULT_META)
                categories.append({
                    "name": entry.name,
                    "payload_count": payload_count,
                    "severity": meta["severity"],
                    "cwe": meta["cwe"],
                    "owasp": meta["owasp"],
                })
        return categories

    @classmethod
    def load_category(cls, category_name: str) -> List[str]:
        """Load all injectable payloads from a category, with caching."""
        if category_name in cls._cache:
            return cls._cache[category_name]

        category_dir = PAYLOADS_DIR / category_name
        if not category_dir.exists():
            logger.warning(f"Category not found: {category_name}")
            return []

        payloads: List[str] = []

        # 1. Load from Intruder/Intruders/Files sub-directories
        for sub_dir_name in INTRUDER_DIRS:
            sub_dir = category_dir / sub_dir_name
            if sub_dir.exists() and sub_dir.is_dir():
                payloads.extend(cls._load_txt_files(sub_dir))

        # 2. Load root-level .txt files (some categories store them here)
        payloads.extend(cls._load_txt_files(category_dir))

        # Deduplicate and trim
        seen: Set[str] = set()
        unique: List[str] = []
        for p in payloads:
            cleaned = p.strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                unique.append(cleaned)

        # Smart stride-sampling: pick evenly-spaced payloads across the full
        # list so we test diverse attack vectors, not just the first N.
        if len(unique) > MAX_PAYLOADS_PER_CATEGORY:
            total = len(unique)
            logger.info(
                f"Category '{category_name}' has {total} payloads, "
                f"stride-sampling to {MAX_PAYLOADS_PER_CATEGORY}"
            )
            step = total / MAX_PAYLOADS_PER_CATEGORY
            unique = [unique[int(i * step)] for i in range(MAX_PAYLOADS_PER_CATEGORY)]

        cls._cache[category_name] = unique
        logger.info(f"Loaded {len(unique)} payloads for '{category_name}'")
        return unique

    @classmethod
    def _count_payloads_in(cls, category_dir: Path) -> int:
        """Quick count of payload lines in a category directory."""
        count = 0
        for txt_path in category_dir.rglob("*.txt"):
            try:
                count += sum(
                    1 for line in txt_path.read_text(errors="ignore").splitlines()
                    if line.strip() and not line.strip().startswith("#")
                )
            except Exception:
                pass
        return min(count, MAX_PAYLOADS_PER_CATEGORY)

    @classmethod
    def _load_txt_files(cls, directory: Path) -> List[str]:
        """Load all non-comment, non-empty lines from .txt files in a dir."""
        lines: List[str] = []
        for txt_file in sorted(directory.glob("*.txt")):
            try:
                content = txt_file.read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines():
                    stripped = line.strip()
                    # Skip comments, markdown headers, and empty lines
                    if stripped and not stripped.startswith(("#", "//", "---")):
                        lines.append(stripped)
            except Exception as e:
                logger.debug(f"Failed to read {txt_file}: {e}")
        return lines


# ── Detection Engine ──────────────────────────────────────────────────────────

class VerificationNeed(str, Enum):
    """What kind of secondary verification a candidate detection needs."""
    NONE = "none"              # Already confirmed (e.g., SSTI canary math)
    TIME_BASED = "time_based"  # Needs correlated timing requests
    BOOLEAN = "boolean"        # Needs true/false condition toggle
    REFLECTION = "reflection"  # Needs probe injection to confirm rendering


@dataclass
class DetectionCandidate:
    """A potential (unverified) vulnerability detection."""
    type: str
    detail: str
    confidence: str                # initial confidence before verification
    needs_verification: VerificationNeed = VerificationNeed.NONE
    verification_context: Optional[Dict[str, Any]] = field(default=None)

    def to_dict(self) -> Dict[str, str]:
        return {"type": self.type, "detail": self.detail, "confidence": self.confidence}


# Type alias for inject functions passed to the verifier
InjectFn = Callable[[str], Coroutine[Any, Any, Tuple[int, str, float]]]


class DetectionEngine:
    """Category-aware detection strategies for analysing HTTP responses."""

    @staticmethod
    def _is_nosql_payload(payload: str) -> bool:
        """Determine if a payload is NoSQL-style based on its structure."""
        payload_lower = payload.lower().strip()
        for marker in NOSQL_PAYLOAD_MARKERS:
            if marker.lower() in payload_lower:
                return True
        # JSON-like payloads with $ operators
        if payload_lower.startswith("{") and "$" in payload_lower:
            return True
        return False

    @staticmethod
    def detect(
        category: str,
        payload: str,
        response_text: str,
        response_status: int,
        response_time: float,
        baseline_status: int,
        baseline_length: int,
        baseline_time: float,
    ) -> Optional[DetectionCandidate]:
        """
        Determine if a response indicates a potential injection.

        Returns a DetectionCandidate if suspicious, else None.
        Candidates with needs_verification != NONE must be verified
        by the ResponseVerifier before being reported as findings.
        """
        cat_lower = category.lower()
        is_nosql = DetectionEngine._is_nosql_payload(payload)

        # ── NoSQL Injection (checked before SQL to avoid misclassification) ──
        if "nosql" in cat_lower or ("sql" in cat_lower and is_nosql):
            nosql_match = NOSQL_ERROR_RE.search(response_text)
            if nosql_match:
                return DetectionCandidate(
                    type="NoSQL Injection",
                    detail=f"NoSQL error pattern: {nosql_match.group()[:80]}",
                    confidence="high",
                    needs_verification=VerificationNeed.NONE,
                )
            # Boolean-based: response differs significantly from baseline
            resp_len = len(response_text)
            len_diff = abs(resp_len - baseline_length)
            if len_diff > 200 and response_status == baseline_status:
                return DetectionCandidate(
                    type="NoSQL Injection (Boolean-Based)",
                    detail=f"Response length changed by {len_diff} bytes with NoSQL operator payload",
                    confidence="low",
                    needs_verification=VerificationNeed.BOOLEAN,
                )
            return None  # prevent fall-through to SQL

        # ── SQL Injection ────────────────────────────────────────────
        if "sql" in cat_lower:
            match = SQL_ERROR_RE.search(response_text)
            if match:
                return DetectionCandidate(
                    type="SQL Injection (Error-Based)",
                    detail=f"SQL error pattern detected: {match.group()[:80]}",
                    confidence="high",
                    needs_verification=VerificationNeed.NONE,
                )
            # Time-based blind: response >5s slower than baseline → needs verification
            delay = response_time - baseline_time
            if delay > 5.0:
                return DetectionCandidate(
                    type="SQL Injection (Time-Based Blind)",
                    detail=f"Response delayed by {delay:.1f}s (baseline: {baseline_time:.1f}s)",
                    confidence="low",
                    needs_verification=VerificationNeed.TIME_BASED,
                    verification_context={"original_delay": delay},
                )

        # ── XSS ──────────────────────────────────────────────────────
        if "xss" in cat_lower:
            # Full payload reflected — still needs context verification
            if payload in response_text:
                has_executable = any(
                    tok in payload.lower() for tok in XSS_EXECUTABLE_TOKENS
                )
                if has_executable:
                    return DetectionCandidate(
                        type="Cross-Site Scripting (XSS)",
                        detail="Executable payload reflected unencoded in response body",
                        confidence="medium",
                        needs_verification=VerificationNeed.REFLECTION,
                    )
            # Partial token reflection — only complete tokens, not substrings
            for token in XSS_EXECUTABLE_TOKENS:
                if token in payload.lower():
                    token_idx = response_text.lower().find(token)
                    if token_idx >= 0:
                        # Verify it's not entity-encoded nearby
                        surrounding = response_text[
                            max(0, token_idx - 5):token_idx + len(token) + 5
                        ]
                        if "&lt;" not in surrounding and "&gt;" not in surrounding:
                            return DetectionCandidate(
                                type="Cross-Site Scripting (XSS)",
                                detail=f"XSS token '{token}' reflected unencoded",
                                confidence="low",
                                needs_verification=VerificationNeed.REFLECTION,
                            )

        # ── SSTI ─────────────────────────────────────────────────────
        if "template" in cat_lower or "ssti" in cat_lower:
            if SSTI_CANARY_RESULT in response_text and SSTI_CANARY_RESULT not in payload:
                return DetectionCandidate(
                    type="Server-Side Template Injection (SSTI)",
                    detail=f"Template expression evaluated: canary '{SSTI_CANARY_RESULT}' found in response",
                    confidence="high",
                    needs_verification=VerificationNeed.NONE,
                )
            if "49" in response_text and "7*7" in payload:
                return DetectionCandidate(
                    type="Server-Side Template Injection (SSTI)",
                    detail="Math expression '7*7=49' evaluated by server",
                    confidence="high",
                    needs_verification=VerificationNeed.NONE,
                )

        # ── Command Injection ────────────────────────────────────────
        if "command" in cat_lower or "cmd" in cat_lower:
            if CMDI_CANARY in response_text:
                return DetectionCandidate(
                    type="OS Command Injection",
                    detail=f"Command injection canary '{CMDI_CANARY}' found in response",
                    confidence="high",
                    needs_verification=VerificationNeed.NONE,
                )
            for indicator in PATH_TRAVERSAL_INDICATORS:
                if indicator in response_text:
                    return DetectionCandidate(
                        type="OS Command Injection",
                        detail=f"System file content indicator: '{indicator}'",
                        confidence="medium",
                        needs_verification=VerificationNeed.NONE,
                    )

        # ── XXE ──────────────────────────────────────────────────────
        if "xxe" in cat_lower:
            for indicator in XXE_INDICATORS:
                if indicator in response_text:
                    return DetectionCandidate(
                        type="XML External Entity (XXE)",
                        detail=f"XXE indicator found: '{indicator}'",
                        confidence="high",
                        needs_verification=VerificationNeed.NONE,
                    )

        # ── Directory / Path Traversal ───────────────────────────────
        if "traversal" in cat_lower or "path" in cat_lower or "inclusion" in cat_lower:
            for indicator in PATH_TRAVERSAL_INDICATORS:
                if indicator in response_text:
                    return DetectionCandidate(
                        type="Directory Traversal",
                        detail=f"Path traversal indicator: '{indicator}'",
                        confidence="high",
                        needs_verification=VerificationNeed.NONE,
                    )

        # ── Open Redirect ────────────────────────────────────────────
        if "redirect" in cat_lower:
            if response_status in (301, 302, 303, 307, 308):
                return DetectionCandidate(
                    type="Open Redirect",
                    detail=f"Redirect status {response_status} triggered by payload",
                    confidence="medium",
                    needs_verification=VerificationNeed.NONE,
                )

        # ── SSRF ─────────────────────────────────────────────────────
        if "ssrf" in cat_lower:
            ssrf_indicators = ["localhost", "127.0.0.1", "169.254.169.254", "metadata"]
            for ind in ssrf_indicators:
                if ind in response_text and ind not in payload:
                    return DetectionCandidate(
                        type="Server-Side Request Forgery (SSRF)",
                        detail=f"SSRF indicator '{ind}' appeared in response",
                        confidence="medium",
                        needs_verification=VerificationNeed.NONE,
                    )

        # ── CRLF ─────────────────────────────────────────────────────
        if "crlf" in cat_lower:
            if response_status == 200 and ("\r\n" in payload or "%0d%0a" in payload.lower()):
                if "Set-Cookie:" in response_text or "X-Injected:" in response_text:
                    return DetectionCandidate(
                        type="CRLF Injection",
                        detail="Injected header content detected in response",
                        confidence="medium",
                        needs_verification=VerificationNeed.NONE,
                    )

        # ── No generic anomaly fallback ──────────────────────────────
        # The old generic anomaly detector (status 500 / length diff) produced
        # too many false positives. Only category-specific signatures are used.

        return None


# ── Response Verifier ─────────────────────────────────────────────────────────

class ResponseVerifier:
    """
    Performs secondary verification requests to confirm detection candidates.

    Eliminates false positives caused by:
      - Network jitter triggering time-based detections
      - Normal response variations matching anomaly thresholds
      - Reflected payloads that are actually HTML-encoded
    """

    def __init__(self, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore):
        self._session = session
        self._sem = semaphore

    async def verify(
        self,
        candidate: DetectionCandidate,
        inject_fn: InjectFn,
        category: str,
        payload: str,
        baseline: Tuple[int, int, float],
    ) -> Optional[DetectionCandidate]:
        """
        Verify a detection candidate. Returns an upgraded candidate if
        confirmed, or None if the finding was a false positive.

        inject_fn: async callable(payload) -> (status, body, elapsed)
        """
        need = candidate.needs_verification

        if need == VerificationNeed.NONE:
            return candidate  # already confirmed

        if need == VerificationNeed.TIME_BASED:
            return await self._verify_time_based(candidate, inject_fn, payload, baseline)

        if need == VerificationNeed.BOOLEAN:
            return await self._verify_boolean(candidate, inject_fn, payload, baseline)

        if need == VerificationNeed.REFLECTION:
            return await self._verify_reflection(candidate, inject_fn, payload)

        return candidate  # unknown type, pass through

    async def _verify_time_based(
        self,
        candidate: DetectionCandidate,
        inject_fn: InjectFn,
        payload: str,
        baseline: Tuple[int, int, float],
    ) -> Optional[DetectionCandidate]:
        """
        Send two requests with different sleep durations.
        If both delays are proportional to the injected sleep, confirm.
        """
        async with self._sem:
            try:
                short_payload = self._replace_sleep_value(payload, VERIFY_TIME_SHORT)
                long_payload = self._replace_sleep_value(payload, VERIFY_TIME_LONG)

                if short_payload == long_payload:
                    logger.debug("Cannot verify time-based: unable to modify sleep in payload")
                    return None

                # Short sleep request
                _, _, elapsed_short = await inject_fn(short_payload)

                # Long sleep request
                _, _, elapsed_long = await inject_fn(long_payload)

                baseline_time = baseline[2]
                net_short = elapsed_short - baseline_time
                net_long = elapsed_long - baseline_time

                # Both must be positive and the long must be sufficiently greater
                expected_delta = VERIFY_TIME_LONG - VERIFY_TIME_SHORT  # 2s
                actual_delta = net_long - net_short

                if (
                    net_short >= VERIFY_TIME_SHORT * VERIFY_TIME_TOLERANCE
                    and actual_delta >= expected_delta * VERIFY_TIME_TOLERANCE
                ):
                    candidate.confidence = "high"
                    candidate.detail = (
                        f"Confirmed: {VERIFY_TIME_SHORT}s sleep → {elapsed_short:.1f}s, "
                        f"{VERIFY_TIME_LONG}s sleep → {elapsed_long:.1f}s "
                        f"(baseline {baseline_time:.1f}s)"
                    )
                    logger.info(f"✓ Time-based verification PASSED for {candidate.type}")
                    return candidate
                else:
                    logger.info(
                        f"✗ Time-based verification FAILED: "
                        f"short={elapsed_short:.1f}s long={elapsed_long:.1f}s "
                        f"(expected delta ≥{expected_delta * VERIFY_TIME_TOLERANCE:.1f}s)"
                    )
                    return None

            except Exception as e:
                logger.debug(f"Time-based verification error: {e}")
                return None

    async def _verify_boolean(
        self,
        candidate: DetectionCandidate,
        inject_fn: InjectFn,
        payload: str,
        baseline: Tuple[int, int, float],
    ) -> Optional[DetectionCandidate]:
        """
        Send a "true" condition and a "false" condition.
        If the response lengths diverge predictably, confirm.
        """
        async with self._sem:
            try:
                true_payload = payload
                false_payload = self._build_false_condition(payload)

                if false_payload == true_payload:
                    logger.debug("Cannot verify boolean: unable to invert condition")
                    return None

                _, body_true, _ = await inject_fn(true_payload)
                _, body_false, _ = await inject_fn(false_payload)

                len_true = len(body_true)
                len_false = len(body_false)
                baseline_len = baseline[1]

                # True condition should differ from baseline; false should be close
                true_diff = abs(len_true - baseline_len)
                false_diff = abs(len_false - baseline_len)

                if true_diff > 100 and false_diff < true_diff * 0.3:
                    candidate.confidence = "high"
                    candidate.detail = (
                        f"Confirmed: true-condition response {len_true} bytes, "
                        f"false-condition {len_false} bytes (baseline {baseline_len} bytes)"
                    )
                    logger.info(f"✓ Boolean verification PASSED for {candidate.type}")
                    return candidate
                else:
                    logger.info(
                        f"✗ Boolean verification FAILED: "
                        f"true_diff={true_diff}, false_diff={false_diff}"
                    )
                    return None

            except Exception as e:
                logger.debug(f"Boolean verification error: {e}")
                return None

    async def _verify_reflection(
        self,
        candidate: DetectionCandidate,
        inject_fn: InjectFn,
        payload: str,
    ) -> Optional[DetectionCandidate]:
        """
        Inject a unique harmless probe tag and check if it appears
        unencoded in the response. If the app HTML-encodes, it's a false positive.
        """
        async with self._sem:
            try:
                _, body, _ = await inject_fn(VERIFY_XSS_PROBE)

                if VERIFY_XSS_PROBE in body:
                    # Probe came back unencoded — real XSS
                    candidate.confidence = "high"
                    candidate.detail = (
                        f"Confirmed: probe tag '{VERIFY_XSS_PROBE}' reflected unencoded. "
                        f"Original: {candidate.detail}"
                    )
                    logger.info(f"✓ Reflection verification PASSED for {candidate.type}")
                    return candidate
                elif VERIFY_XSS_ENCODED in body:
                    logger.info("✗ Reflection verification FAILED: probe was HTML-encoded")
                    return None
                else:
                    logger.info("✗ Reflection verification FAILED: probe not reflected")
                    return None

            except Exception as e:
                logger.debug(f"Reflection verification error: {e}")
                return None

    # ── Helper Methods ────────────────────────────────────────────────────

    @staticmethod
    def _replace_sleep_value(payload: str, seconds: int) -> str:
        """
        Replace sleep/waitfor/delay numeric values in a payload.
        E.g., "SLEEP(10)" → "SLEEP(2)", "pg_sleep(10)" → "pg_sleep(2)"
        """
        patterns = [
            (r"(?i)(SLEEP)\((\d+)\)", f"SLEEP({seconds})"),
            (r"(?i)(pg_sleep)\((\d+)\)", f"pg_sleep({seconds})"),
            (r"(?i)(WAITFOR\s+DELAY\s+')(\d{2}):(\d{2}):(\d{2})'",
             f"WAITFOR DELAY '00:00:{seconds:02d}'"),
            (r"(?i)(DBMS_LOCK\.SLEEP)\((\d+)\)", f"DBMS_LOCK.SLEEP({seconds})"),
        ]
        for pattern, replacement in patterns:
            new_result = re.sub(pattern, replacement, payload)
            if new_result != payload:
                return new_result

        # Fallback: replace the first standalone large number
        fallback = re.sub(r"\b(\d{2,})\b", str(seconds), payload, count=1)
        return fallback

    @staticmethod
    def _build_false_condition(payload: str) -> str:
        """
        Convert a NoSQL/boolean true-condition payload to a false-condition.
        E.g., {"$ne": 1} → {"$eq": "__vortex_false__"}
        """
        swap_pairs = [
            ("$ne", "$eq"),
            ("$gt", "$lt"),
            ("$gte", "$lte"),
        ]
        result = payload
        for old, new in swap_pairs:
            if old in result:
                result = result.replace(old, new, 1)
                # Replace the comparison value to make the condition definitely false
                result = result.replace(": 1", ': "__vortex_false__"', 1)
                result = result.replace(":1", ':"__vortex_false__"', 1)
                return result

        # Try swapping $exists true→false
        if '"$exists": true' in result:
            return result.replace('"$exists": true', '"$exists": false', 1)
        if '"$exists":true' in result:
            return result.replace('"$exists":true', '"$exists":false', 1)

        # Generic fallback: append an impossible condition string
        return payload + "__vortex_false__"


# ── Injectable Point Models ───────────────────────────────────────────────────

class InjectableParam:
    """Represents a URL parameter that can receive payloads."""

    __slots__ = ("url", "param_name", "original_value")

    def __init__(self, url: str, param_name: str, original_value: str):
        self.url = url
        self.param_name = param_name
        self.original_value = original_value

    def inject(self, payload: str) -> str:
        """Return the full URL with this parameter replaced by the payload."""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        # Replace only this parameter
        params[self.param_name] = [payload]
        # Rebuild query string (flatten single-value lists)
        new_query = urlencode(
            {k: v[0] if len(v) == 1 else v for k, v in params.items()},
            doseq=True,
        )
        return urlunparse(parsed._replace(query=new_query))


class InjectableForm:
    """Represents a form field that can receive payloads."""

    __slots__ = ("action_url", "method", "field_name", "all_fields")

    def __init__(
        self,
        action_url: str,
        method: str,
        field_name: str,
        all_fields: Dict[str, str],
    ):
        self.action_url = action_url
        self.method = method.upper()
        self.field_name = field_name
        self.all_fields = all_fields

    def inject(self, payload: str) -> Tuple[str, str, Dict[str, str]]:
        """Return (url, method, form_data) with this field set to the payload."""
        data = dict(self.all_fields)
        data[self.field_name] = payload
        return self.action_url, self.method, data


# ── VortexScanner ─────────────────────────────────────────────────────────────

@ScannerRegistry.register
class VortexScanner(BaseScanner):
    """
    Deep vulnerability scanner powered by the payload library.

    Loads payload files from user-selected vulnerability categories and
    injects them into every discovered injectable point from the attack surface.
    Every detection candidate is verified before being reported as a finding.
    """

    @property
    def name(self) -> str:
        return "vortex"

    @property
    def display_name(self) -> str:
        return "Vortex Deep Scanner"

    @property
    def description(self) -> str:
        return (
            "Deep vulnerability testing using 70+ payload categories. "
            "Injects payloads into every discovered parameter and form field "
            "with built-in verification to eliminate false positives."
        )

    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        """Execute deep payload-based vulnerability scanning with verification.

        Uses a streaming worker pool instead of pre-building all coroutines.
        Implements short-circuiting: once a vulnerability is confirmed on a
        (point, category) pair, remaining payloads for that pair are skipped.
        """
        attack_surface = kwargs.get("attack_surface", {})
        categories = kwargs.get("vortex_categories", [])

        if not categories:
            categories = self._auto_select_categories()
            logger.info(f"No categories specified, auto-selected: {categories}")

        self.report_progress(0.0, f"Starting Vortex scan with {len(categories)} categories")

        # 1. Discover injectable points (capped to avoid explosion)
        injectable_params = self._extract_params(target, attack_surface)[:MAX_INJECTABLE_POINTS]
        injectable_forms = self._extract_forms(target, attack_surface)[:MAX_INJECTABLE_POINTS]

        total_points = len(injectable_params) + len(injectable_forms)
        if total_points == 0:
            self.report_progress(100.0, "No injectable points found in attack surface")
            return [
                Finding(
                    scanner=self.name,
                    type="Vortex Info",
                    severity="info",
                    title="No injectable parameters found",
                    description=(
                        "The crawler did not discover any URL parameters or form fields "
                        "to inject payloads into. Consider running the Crawler scanner first."
                    ),
                )
            ]

        logger.info(
            f"Found {len(injectable_params)} URL params and "
            f"{len(injectable_forms)} form fields across attack surface"
        )

        # 2. Load payloads for each category
        category_payloads: Dict[str, List[str]] = {}
        total_payloads = 0
        for cat in categories:
            payloads = PayloadLoader.load_category(cat)
            if payloads:
                category_payloads[cat] = payloads
                total_payloads += len(payloads)

        if total_payloads == 0:
            self.report_progress(100.0, "No payloads loaded from selected categories")
            return []

        # Calculate total test count for progress reporting
        task_count = total_payloads * total_points

        self.report_progress(
            5.0,
            f"Loaded {total_payloads} payloads across {len(category_payloads)} categories, "
            f"testing {total_points} points ({task_count} tests)",
        )

        # 3. Streaming worker pool with short-circuiting
        findings: List[Finding] = []
        seen_findings: Set[str] = set()
        # Track (point_key, category) pairs that already have a confirmed vuln
        exploited: Set[str] = set()
        semaphore = asyncio.Semaphore(DEFAULT_CONCURRENCY)
        connector = aiohttp.TCPConnector(limit=DEFAULT_CONCURRENCY, ssl=False)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        ) as session:
            verifier = ResponseVerifier(session, semaphore)
            baselines = await self._collect_baselines(session, injectable_params, injectable_forms)

            completed = 0
            self.report_progress(10.0, f"Running {task_count} injection tests...")

            # Process one (category, point) group at a time.
            # Within each group, batch payloads for concurrency.
            for cat_name, payloads in category_payloads.items():
                meta = CATEGORY_META.get(cat_name, DEFAULT_META)

                # ── Test URL parameters ──────────────────────────────
                for param in injectable_params:
                    point_key = f"{cat_name}|param|{param.url}:{param.param_name}"
                    if point_key in exploited:
                        completed += len(payloads)
                        continue

                    baseline = baselines.get(param.url, (200, 0, 0.5))
                    found_for_point = False

                    for batch_start in range(0, len(payloads), MAX_BATCH_SIZE):
                        if found_for_point:
                            # Short-circuit: skip remaining payload batches
                            completed += len(payloads) - batch_start
                            break

                        batch = payloads[batch_start:batch_start + MAX_BATCH_SIZE]
                        batch_tasks = [
                            self._test_param(
                                session, semaphore, verifier,
                                cat_name, meta, param, p, baseline,
                            )
                            for p in batch
                        ]

                        results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                        completed += len(batch)

                        for result in results:
                            if isinstance(result, Finding):
                                dedup_key = f"{result.type}|{result.location}"
                                if dedup_key not in seen_findings:
                                    seen_findings.add(dedup_key)
                                    findings.append(result)
                                    found_for_point = True
                                    exploited.add(point_key)

                        # Progress update
                        pct = 10.0 + (completed / max(task_count, 1)) * 85.0
                        self.report_progress(
                            pct,
                            f"Tested {completed}/{task_count} "
                            f"({len(findings)} verified findings)",
                        )

                # ── Test form fields ─────────────────────────────────
                for form in injectable_forms:
                    point_key = f"{cat_name}|form|{form.action_url}:{form.field_name}"
                    if point_key in exploited:
                        completed += len(payloads)
                        continue

                    baseline = baselines.get(form.action_url, (200, 0, 0.5))
                    found_for_point = False

                    for batch_start in range(0, len(payloads), MAX_BATCH_SIZE):
                        if found_for_point:
                            completed += len(payloads) - batch_start
                            break

                        batch = payloads[batch_start:batch_start + MAX_BATCH_SIZE]
                        batch_tasks = [
                            self._test_form(
                                session, semaphore, verifier,
                                cat_name, meta, form, p, baseline,
                            )
                            for p in batch
                        ]

                        results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                        completed += len(batch)

                        for result in results:
                            if isinstance(result, Finding):
                                dedup_key = f"{result.type}|{result.location}"
                                if dedup_key not in seen_findings:
                                    seen_findings.add(dedup_key)
                                    findings.append(result)
                                    found_for_point = True
                                    exploited.add(point_key)

                        pct = 10.0 + (completed / max(task_count, 1)) * 85.0
                        self.report_progress(
                            pct,
                            f"Tested {completed}/{task_count} "
                            f"({len(findings)} verified findings)",
                        )

        self.report_progress(
            100.0,
            f"Vortex complete: {len(findings)} verified vulns "
            f"({len(exploited)} short-circuited)",
        )
        return findings

    # ── Private Methods ───────────────────────────────────────────────────

    def _auto_select_categories(self) -> List[str]:
        """Select highest-impact categories when user doesn't specify any."""
        priority = [
            "SQL Injection",
            "XSS Injection",
            "Command Injection",
        ]
        available = {c["name"] for c in PayloadLoader.discover_categories()}
        return [c for c in priority if c in available][:3]

    def _extract_params(
        self, target: str, attack_surface: Dict[str, Any]
    ) -> List[InjectableParam]:
        """Extract injectable URL parameters from attack surface data."""
        params: List[InjectableParam] = []
        seen: Set[str] = set()

        # From the attack_surface.parameters list (query string parameters)
        for param_entry in attack_surface.get("parameters", []):
            if isinstance(param_entry, str) and "=" in param_entry:
                pass  # handled by URL parsing below

        # From internal URLs — find any with query parameters
        urls_to_scan = set()
        for url in attack_surface.get("internal_urls", []):
            parsed = urlparse(url)
            if parsed.query:
                urls_to_scan.add(url)

        # Also include target URL itself if it has params
        parsed_target = urlparse(target if "://" in target else f"https://{target}")
        if parsed_target.query:
            urls_to_scan.add(target)

        for url in urls_to_scan:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for pname, pvalues in query_params.items():
                key = f"{parsed.netloc}{parsed.path}:{pname}"
                if key not in seen:
                    seen.add(key)
                    params.append(
                        InjectableParam(url, pname, pvalues[0] if pvalues else "")
                    )

        return params

    def _extract_forms(
        self, target: str, attack_surface: Dict[str, Any]
    ) -> List[InjectableForm]:
        """Extract injectable form fields from attack surface data."""
        forms: List[InjectableForm] = []
        seen: Set[str] = set()

        for form_data in attack_surface.get("forms", []):
            action = form_data.get("action", "")
            method = form_data.get("method", "GET")
            inputs = form_data.get("inputs", [])

            if not action:
                continue

            # Resolve relative action URLs
            if not action.startswith("http"):
                base = target if "://" in target else f"https://{target}"
                if action.startswith("/"):
                    parsed_base = urlparse(base)
                    action = f"{parsed_base.scheme}://{parsed_base.netloc}{action}"
                else:
                    action = f"{base.rstrip('/')}/{action}"

            # Build field map with defaults
            all_fields: Dict[str, str] = {}
            for inp in inputs:
                name = inp.get("name", "")
                if name:
                    all_fields[name] = inp.get("value", "test")

            # Create an injectable point for each text-like input
            for inp in inputs:
                name = inp.get("name", "")
                input_type = inp.get("type", "text").lower()
                if not name:
                    continue
                # Skip non-injectable types
                if input_type in ("submit", "button", "image", "file", "reset"):
                    continue

                key = f"{action}:{name}"
                if key not in seen:
                    seen.add(key)
                    forms.append(InjectableForm(action, method, name, all_fields))

        return forms

    async def _collect_baselines(
        self,
        session: aiohttp.ClientSession,
        params: List[InjectableParam],
        forms: List[InjectableForm],
    ) -> Dict[str, Tuple[int, int, float]]:
        """Collect baseline responses (status, length, time) for URLs."""
        baselines: Dict[str, Tuple[int, int, float]] = {}
        urls_to_baseline = set()

        for p in params:
            urls_to_baseline.add(p.url)
        for f in forms:
            urls_to_baseline.add(f.action_url)

        for url in urls_to_baseline:
            try:
                start = time.monotonic()
                async with session.get(url) as resp:
                    body = await resp.text()
                    elapsed = time.monotonic() - start
                    baselines[url] = (resp.status, len(body), elapsed)
            except Exception:
                baselines[url] = (200, 0, 0.5)

        return baselines

    async def _test_param(
        self,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        verifier: ResponseVerifier,
        category: str,
        meta: Dict[str, Any],
        param: InjectableParam,
        payload: str,
        baseline: Tuple[int, int, float],
    ) -> Optional[Finding]:
        """Test a single payload against a URL parameter, with verification."""
        async with semaphore:
            try:
                injected_url = param.inject(payload)
                start = time.monotonic()

                async with session.get(injected_url) as resp:
                    body = await resp.text()
                    elapsed = time.monotonic() - start

                candidate = DetectionEngine.detect(
                    category=category,
                    payload=payload,
                    response_text=body,
                    response_status=resp.status,
                    response_time=elapsed,
                    baseline_status=baseline[0],
                    baseline_length=baseline[1],
                    baseline_time=baseline[2],
                )

                if candidate:
                    # Build an inject function for the verifier
                    async def param_inject_fn(p: str) -> Tuple[int, str, float]:
                        url = param.inject(p)
                        s = time.monotonic()
                        async with session.get(url) as r:
                            b = await r.text()
                            e = time.monotonic() - s
                        return r.status, b, e

                    verified = await verifier.verify(
                        candidate, param_inject_fn, category, payload, baseline
                    )
                    if verified:
                        return self._build_finding(
                            category, meta, verified.to_dict(), payload,
                            location=f"URL param '{param.param_name}' at {param.url}",
                        )

            except asyncio.TimeoutError:
                pass  # Timeouts handled by verification — no auto-report
            except Exception:
                pass

        return None

    async def _test_form(
        self,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        verifier: ResponseVerifier,
        category: str,
        meta: Dict[str, Any],
        form: InjectableForm,
        payload: str,
        baseline: Tuple[int, int, float],
    ) -> Optional[Finding]:
        """Test a single payload against a form field, with verification."""
        async with semaphore:
            try:
                action_url, method, form_data = form.inject(payload)
                start = time.monotonic()

                if method == "POST":
                    async with session.post(action_url, data=form_data) as resp:
                        body = await resp.text()
                        elapsed = time.monotonic() - start
                else:
                    async with session.get(action_url, params=form_data) as resp:
                        body = await resp.text()
                        elapsed = time.monotonic() - start

                candidate = DetectionEngine.detect(
                    category=category,
                    payload=payload,
                    response_text=body,
                    response_status=resp.status,
                    response_time=elapsed,
                    baseline_status=baseline[0],
                    baseline_length=baseline[1],
                    baseline_time=baseline[2],
                )

                if candidate:
                    # Build an inject function for the verifier
                    async def form_inject_fn(p: str) -> Tuple[int, str, float]:
                        _, _, fd = form.inject(p)
                        s = time.monotonic()
                        if method == "POST":
                            async with session.post(action_url, data=fd) as r:
                                b = await r.text()
                                e = time.monotonic() - s
                        else:
                            async with session.get(action_url, params=fd) as r:
                                b = await r.text()
                                e = time.monotonic() - s
                        return r.status, b, e

                    verified = await verifier.verify(
                        candidate, form_inject_fn, category, payload, baseline
                    )
                    if verified:
                        return self._build_finding(
                            category, meta, verified.to_dict(), payload,
                            location=f"Form field '{form.field_name}' → {form.action_url}",
                        )

            except asyncio.TimeoutError:
                pass  # Timeouts handled by verification — no auto-report
            except Exception:
                pass

        return None

    def _build_finding(
        self,
        category: str,
        meta: Dict[str, Any],
        detection: Dict[str, str],
        payload: str,
        location: str,
    ) -> Finding:
        """Construct a Finding from verified detection results."""
        confidence = detection.get("confidence", "low")

        # Adjust severity based on confidence
        severity = meta["severity"]
        if confidence == "low" and severity in ("critical", "high"):
            severity = "medium"

        return Finding(
            scanner=self.name,
            type=detection["type"],
            severity=severity,
            title=f"{detection['type']} detected via Vortex",
            description=detection["detail"],
            evidence=f"Payload: {payload[:200]}",
            location=location,
            remediation=self._get_remediation(category),
            cwe_id=meta["cwe"],
            owasp_category=meta.get("owasp"),
        )

    @staticmethod
    def _get_remediation(category: str) -> str:
        """Return category-specific remediation guidance."""
        remediations = {
            "SQL Injection": (
                "Use parameterized queries / prepared statements. "
                "Apply input validation and restrict database privileges."
            ),
            "NoSQL Injection": (
                "Validate and sanitize all user input before constructing NoSQL queries. "
                "Use allowlists for query operators. Avoid passing raw user input to query selectors."
            ),
            "XSS Injection": (
                "Encode all user input before rendering in HTML. "
                "Use Content-Security-Policy headers. Implement output encoding."
            ),
            "Command Injection": (
                "Never pass user input to system commands. "
                "Use safe APIs (subprocess with shell=False). Validate and sanitize inputs."
            ),
            "Server Side Template Injection": (
                "Use logic-less templates when possible. "
                "Sandbox template engines. Never render user input as template code."
            ),
            "Directory Traversal": (
                "Validate file paths against a whitelist. "
                "Use chroot/jail. Normalize and canonicalize paths before use."
            ),
            "XXE Injection": (
                "Disable external entity processing in XML parsers. "
                "Use JSON instead of XML. Validate and sanitize XML input."
            ),
            "Server Side Request Forgery": (
                "Validate and whitelist allowed URLs. "
                "Block internal/private IP ranges. Use network-level controls."
            ),
        }
        return remediations.get(category, f"Apply input validation and encoding for {category}.")
