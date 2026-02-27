"""
Technology Fingerprinting Scanner.

Detects the target's technology stack by analyzing:
- HTTP response headers (Server, X-Powered-By)
- Cookie naming patterns (PHPSESSID, JSESSIONID, etc.)
- HTML meta tags and generators
- JavaScript framework signatures in page source
- URL file extension patterns
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

import aiohttp

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import normalize_target


# ── Fingerprint Signatures ──────────────────────────────────

HEADER_SIGNATURES: Dict[str, List[Dict[str, str]]] = {
    "server": [
        {"pattern": r"nginx", "tech": "Nginx", "category": "Web Server"},
        {"pattern": r"apache", "tech": "Apache", "category": "Web Server"},
        {"pattern": r"microsoft-iis", "tech": "Microsoft IIS", "category": "Web Server"},
        {"pattern": r"litespeed", "tech": "LiteSpeed", "category": "Web Server"},
        {"pattern": r"cloudflare", "tech": "Cloudflare", "category": "CDN/WAF"},
        {"pattern": r"gunicorn", "tech": "Gunicorn", "category": "App Server"},
        {"pattern": r"uvicorn", "tech": "Uvicorn", "category": "App Server"},
        {"pattern": r"openresty", "tech": "OpenResty", "category": "Web Server"},
    ],
    "x-powered-by": [
        {"pattern": r"php", "tech": "PHP", "category": "Language"},
        {"pattern": r"asp\.net", "tech": "ASP.NET", "category": "Framework"},
        {"pattern": r"express", "tech": "Express.js", "category": "Framework"},
        {"pattern": r"next\.js", "tech": "Next.js", "category": "Framework"},
        {"pattern": r"servlet", "tech": "Java Servlet", "category": "Framework"},
    ],
}

COOKIE_SIGNATURES: Dict[str, Dict[str, str]] = {
    "phpsessid": {"tech": "PHP", "category": "Language"},
    "jsessionid": {"tech": "Java", "category": "Language"},
    "asp.net_sessionid": {"tech": "ASP.NET", "category": "Framework"},
    "csrftoken": {"tech": "Django", "category": "Framework"},
    "laravel_session": {"tech": "Laravel", "category": "Framework"},
    "_rails_session": {"tech": "Ruby on Rails", "category": "Framework"},
    "connect.sid": {"tech": "Express.js", "category": "Framework"},
    "wp-settings": {"tech": "WordPress", "category": "CMS"},
    "drupal.visitor": {"tech": "Drupal", "category": "CMS"},
    "joomla_user_state": {"tech": "Joomla", "category": "CMS"},
}

JS_SIGNATURES: List[Dict[str, str]] = [
    {"pattern": r"react", "tech": "React", "category": "JS Framework"},
    {"pattern": r"__next", "tech": "Next.js", "category": "JS Framework"},
    {"pattern": r"__nuxt", "tech": "Nuxt.js", "category": "JS Framework"},
    {"pattern": r"ng-version", "tech": "Angular", "category": "JS Framework"},
    {"pattern": r"vue\.js|v-cloak|v-bind", "tech": "Vue.js", "category": "JS Framework"},
    {"pattern": r"jquery", "tech": "jQuery", "category": "JS Library"},
    {"pattern": r"bootstrap", "tech": "Bootstrap", "category": "CSS Framework"},
    {"pattern": r"tailwindcss|tailwind", "tech": "Tailwind CSS", "category": "CSS Framework"},
    {"pattern": r"gatsby", "tech": "Gatsby", "category": "Static Site Generator"},
    {"pattern": r"wp-content|wp-includes", "tech": "WordPress", "category": "CMS"},
    {"pattern": r"drupal\.js", "tech": "Drupal", "category": "CMS"},
    {"pattern": r"recaptcha", "tech": "Google reCAPTCHA", "category": "Security"},
    {"pattern": r"cloudflare", "tech": "Cloudflare", "category": "CDN/WAF"},
    {"pattern": r"google-analytics|gtag\(|ga\(", "tech": "Google Analytics", "category": "Analytics"},
    {"pattern": r"hotjar", "tech": "Hotjar", "category": "Analytics"},
]

META_SIGNATURES: List[Dict[str, str]] = [
    {"pattern": r"wordpress", "tech": "WordPress", "category": "CMS"},
    {"pattern": r"drupal", "tech": "Drupal", "category": "CMS"},
    {"pattern": r"joomla", "tech": "Joomla", "category": "CMS"},
    {"pattern": r"shopify", "tech": "Shopify", "category": "E-Commerce"},
    {"pattern": r"wix\.com", "tech": "Wix", "category": "Website Builder"},
    {"pattern": r"squarespace", "tech": "Squarespace", "category": "Website Builder"},
]


@ScannerRegistry.register
class FingerprintScanner(BaseScanner):

    @property
    def name(self) -> str:
        return "fingerprint"

    @property
    def display_name(self) -> str:
        return "Technology Fingerprinter"

    @property
    def description(self) -> str:
        return "Detect target technology stack via headers, cookies, meta tags, and JS signatures"

    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        url = normalize_target(target)
        findings: List[Finding] = []
        detected_techs: List[Dict[str, str]] = []  # {tech, category, source}
        seen: Set[str] = set()

        self.report_progress(5.0, f"Fingerprinting {url}")

        try:
            timeout_val = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout_val) as session:
                async with session.get(
                    url, ssl=False, allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; VeltroScanner/1.0)"}
                ) as resp:
                    headers = dict(resp.headers)
                    cookies = resp.headers.getall("Set-Cookie", [])
                    body = await resp.text()

        except Exception as exc:
            return [Finding(
                scanner=self.name, type="Connection Failed", severity=Severity.INFO,
                title=f"Cannot fingerprint {url}", description=str(exc), location=url,
            )]

        # ── 1. Header Analysis ─────────────────────────────────
        self.report_progress(20.0, "Analyzing response headers")

        for header_name, signatures in HEADER_SIGNATURES.items():
            header_val = headers.get(header_name, "")
            # Also check case-insensitive
            if not header_val:
                for k, v in headers.items():
                    if k.lower() == header_name:
                        header_val = v
                        break
            if header_val:
                for sig in signatures:
                    if re.search(sig["pattern"], header_val, re.IGNORECASE):
                        key = sig["tech"]
                        if key not in seen:
                            seen.add(key)
                            detected_techs.append({
                                "tech": sig["tech"],
                                "category": sig["category"],
                                "source": f"Header: {header_name}: {header_val}",
                            })

        # ── 2. Cookie Analysis ─────────────────────────────────
        self.report_progress(40.0, "Analyzing cookie patterns")

        for raw_cookie in cookies:
            cookie_name = raw_cookie.split("=")[0].strip().lower() if "=" in raw_cookie else ""
            for pattern, sig in COOKIE_SIGNATURES.items():
                if pattern in cookie_name:
                    key = sig["tech"]
                    if key not in seen:
                        seen.add(key)
                        detected_techs.append({
                            "tech": sig["tech"],
                            "category": sig["category"],
                            "source": f"Cookie: {cookie_name}",
                        })

        # ── 3. HTML Meta Tag Analysis ──────────────────────────
        self.report_progress(60.0, "Scanning HTML meta tags")

        generator_match = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']',
            body, re.IGNORECASE,
        )
        if generator_match:
            gen_value = generator_match.group(1)
            for sig in META_SIGNATURES:
                if re.search(sig["pattern"], gen_value, re.IGNORECASE):
                    key = sig["tech"]
                    if key not in seen:
                        seen.add(key)
                        detected_techs.append({
                            "tech": sig["tech"],
                            "category": sig["category"],
                            "source": f"Meta generator: {gen_value}",
                        })

        # ── 4. JavaScript Framework Signatures ─────────────────
        self.report_progress(80.0, "Detecting JavaScript frameworks")

        body_lower = body.lower()
        for sig in JS_SIGNATURES:
            if re.search(sig["pattern"], body_lower, re.IGNORECASE):
                key = sig["tech"]
                if key not in seen:
                    seen.add(key)
                    detected_techs.append({
                        "tech": sig["tech"],
                        "category": sig["category"],
                        "source": "Page source analysis",
                    })

        # ── 5. Build Findings ──────────────────────────────────
        self.report_progress(95.0, "Building fingerprint report")

        if detected_techs:
            # Group by category for a clean summary
            by_category: Dict[str, List[str]] = {}
            for dt in detected_techs:
                by_category.setdefault(dt["category"], []).append(dt["tech"])

            summary_parts = [f"**{cat}:** {', '.join(techs)}" for cat, techs in by_category.items()]
            summary = " | ".join(summary_parts)

            findings.append(Finding(
                scanner=self.name,
                type="Technology Stack Detected",
                severity=Severity.INFO,
                title=f"Detected {len(detected_techs)} technologies on {urlparse(url).netloc}",
                description=summary,
                evidence="\n".join(f"- {d['tech']} ({d['category']}) via {d['source']}" for d in detected_techs),
                location=url,
            ))

            # Flag specific risky technologies
            risky_techs = {"jQuery": "CWE-1035", "WordPress": "CWE-1035", "Drupal": "CWE-1035"}
            for dt in detected_techs:
                if dt["tech"] in risky_techs:
                    findings.append(Finding(
                        scanner=self.name,
                        type="Known-Vulnerable Technology",
                        severity=Severity.LOW,
                        title=f"{dt['tech']} detected — check for known CVEs",
                        description=(
                            f"{dt['tech']} is a high-value target for attackers. "
                            "Ensure it is running the latest patched version."
                        ),
                        evidence=f"Detected via: {dt['source']}",
                        location=url,
                        remediation=f"Update {dt['tech']} to the latest version and monitor for CVE advisories.",
                        cwe_id=risky_techs[dt["tech"]],
                    ))
        else:
            findings.append(Finding(
                scanner=self.name, type="Fingerprint Analysis", severity=Severity.INFO,
                title="Could not identify specific technologies",
                description="The target does not expose obvious technology signatures.",
                location=url,
            ))

        self.report_progress(100.0, "Fingerprinting complete")
        return findings
