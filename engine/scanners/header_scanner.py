"""
HTTP security header analyzer.

Checks for missing or misconfigured security headers
like HSTS, CSP, X-Frame-Options, etc.
"""

from __future__ import annotations

from typing import Any, List

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import normalize_target, fetch_url


# Expected security headers with severity and remediation
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "HSTS forces browsers to use HTTPS, preventing downgrade attacks.",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "cwe_id": "CWE-319",
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": "CSP prevents XSS by controlling which resources can be loaded.",
        "remediation": "Define a strict CSP policy. Start with: default-src 'self'",
        "cwe_id": "CWE-79",
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "description": "Prevents MIME type sniffing attacks.",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
        "cwe_id": "CWE-16",
    },
    "X-Frame-Options": {
        "severity": Severity.LOW,
        "description": "Prevents clickjacking by controlling iframe embedding. Note: Modern alternative is CSP frame-ancestors.",
        "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN)",
        "cwe_id": "CWE-1021",
    },
    "X-XSS-Protection": {
        "severity": Severity.INFO,
        "description": "Legacy XSS protection. Modern browsers use CSP instead and ignore this header.",
        "remediation": "Add header: X-XSS-Protection: 0 (CSP is preferred, this header is mostly deprecated)",
    },
    "Referrer-Policy": {
        "severity": Severity.INFO,
        "description": "Controls how much referrer info is sent with requests.",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": Severity.INFO,
        "description": "Controls browser features like camera, microphone, geolocation.",
        "remediation": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
}

# Headers that should NOT be present in production
LEAKY_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Debug-Token",
]


@ScannerRegistry.register
class HeaderScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "headers"

    @property
    def display_name(self) -> str:
        return "HTTP Header Analyzer"

    @property
    def description(self) -> str:
        return "Analyze HTTP response headers for missing security controls"

    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        url = normalize_target(target)
        findings: List[Finding] = []

        self.report_progress(10.0, f"Fetching headers from {url}")

        status, _, headers = await fetch_url(url, timeout=self.timeout)

        if status == -1:
            findings.append(Finding(
                scanner=self.name, type="Connection Failed", severity=Severity.INFO,
                title=f"Cannot connect to {url}",
                description="Failed to fetch HTTP response headers.",
                location=url,
            ))
            return findings

        if status in (401, 403, 406, 503):
            findings.append(Finding(
                scanner=self.name, type="WAF Block Detected", severity=Severity.INFO,
                title=f"Potential WAF Block (HTTP {status})",
                description=(
                    f"The server returned an HTTP {status} response. "
                    "This often indicates a Web Application Firewall (WAF) or Edge Proxy (like Akamai or Cloudflare) "
                    "is blocking the scanner. The security headers analyzed below belong to the WAF's block page, "
                    "NOT the actual application backend. Manual verification is highly recommended."
                ),
                location=url,
            ))

        self.report_progress(40.0, "Analyzing security headers")

        # Normalize header names to lower for comparison
        header_lower = {k.lower(): v for k, v in headers.items()}

        # Check for missing security headers
        for header_name, config_info in SECURITY_HEADERS.items():
            if header_name.lower() not in header_lower:
                findings.append(Finding(
                    scanner=self.name,
                    type="Missing Security Header",
                    severity=config_info["severity"],
                    title=f"Missing {header_name} header",
                    description=config_info["description"],
                    location=url,
                    remediation=config_info["remediation"],
                    cwe_id=config_info.get("cwe_id"),
                ))

        self.report_progress(70.0, "Checking for information leakage headers")

        # Check for leaky/info-disclosure headers
        for header_name in LEAKY_HEADERS:
            if header_name.lower() in header_lower:
                value = header_lower[header_name.lower()]
                findings.append(Finding(
                    scanner=self.name,
                    type="Information Disclosure Header",
                    severity=Severity.LOW,
                    title=f"Server leaks info via {header_name}: {value}",
                    description=(
                        f"The '{header_name}' header reveals server technology ({value}). "
                        f"This helps attackers identify specific exploits."
                    ),
                    evidence=f"{header_name}: {value}",
                    location=url,
                    remediation=f"Remove or suppress the '{header_name}' header in production.",
                    cwe_id="CWE-200",
                ))

        if not findings:
            findings.append(Finding(
                scanner=self.name, type="Header Analysis", severity=Severity.INFO,
                title="All critical security headers are present",
                description="The server has proper security headers configured.",
                location=url,
            ))

        self.report_progress(100.0, "Header analysis complete")
        return findings
