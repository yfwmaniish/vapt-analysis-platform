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
        findings = []

        if not attack_surface:
            self.report_progress(100.0, "No attack surface data provided. Run crawler first.")
            return findings

        timeout_val = aiohttp.ClientTimeout(total=self.timeout)
        urls_to_test = attack_surface.get("internal_urls", [])
        forms_to_test = attack_surface.get("forms", [])

        # Filter URLs to only those with query parameters
        param_urls = [u for u in urls_to_test if "?" in u]
        
        # Hard limits to prevent fuzzing from taking hours on massive commercial sites
        param_urls = param_urls[:20]
        forms_to_test = forms_to_test[:10]
        
        total_tests = len(param_urls) + len(forms_to_test)
        if total_tests == 0:
            self.report_progress(100.0, "No inputs or parameters found to fuzz.")
            return findings

        self.report_progress(5.0, f"Fuzzing {len(param_urls)} parameterized URLs and {len(forms_to_test)} forms")

        tested_count = 0

        async with aiohttp.ClientSession(timeout=timeout_val, headers={"User-Agent": "Veltro-Fuzzer/1.0"}) as session:
            
            # 1. Fuzz URLs with query parameters
            for url in param_urls:
                parsed = urlparse(url)
                params = parse_qsl(parsed.query)
                
                # Fuzz each parameter with each payload
                for i, (key, value) in enumerate(params):
                    for sqli in SQLI_PAYLOADS:
                        fuzzed_params = params.copy()
                        fuzzed_params[i] = (key, sqli) # Replace value with payload
                        fuzzed_query = urlencode(fuzzed_params)
                        fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, fuzzed_query, parsed.fragment))
                        
                        finding = await self._test_sqli(session, fuzzed_url, "GET")
                        if finding:
                            findings.append(finding)
                            break # Stop testing this param for SQLi if one works
                    
                    for xss in XSS_PAYLOADS + XSS_POLYGLOT_PAYLOADS:
                        fuzzed_params = params.copy()
                        fuzzed_params[i] = (key, xss)
                        fuzzed_query = urlencode(fuzzed_params)
                        fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, fuzzed_query, parsed.fragment))
                        
                        finding = await self._test_xss(session, fuzzed_url, xss, "GET")
                        if finding:
                            findings.append(finding)
                            break

                    # Test SSTI
                    for ssti in SSTI_PAYLOADS:
                        fuzzed_params = params.copy()
                        fuzzed_params[i] = (key, ssti)
                        fuzzed_query = urlencode(fuzzed_params)
                        fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, fuzzed_query, parsed.fragment))

                        finding = await self._test_ssti(session, fuzzed_url, ssti, "GET")
                        if finding:
                            findings.append(finding)
                            break

                    # Test Command Injection
                    for cmdi in CMDI_PAYLOADS:
                        fuzzed_params = params.copy()
                        fuzzed_params[i] = (key, cmdi)
                        fuzzed_query = urlencode(fuzzed_params)
                        fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, fuzzed_query, parsed.fragment))

                        finding = await self._test_cmdi(session, fuzzed_url, "GET")
                        if finding:
                            findings.append(finding)
                            break
                    
                tested_count += 1
                if total_tests > 0:
                    self.report_progress(5.0 + (tested_count / total_tests * 90.0), "Fuzzing URL parameters")

            # 2. Fuzz Forms
            for form in forms_to_test:
                action = form.get("action")
                method = form.get("method", "GET").upper()
                inputs = form.get("inputs", [])
                
                if not action or not inputs:
                    continue

                for inp in inputs:
                    name = inp.get("name")
                    if not name:
                        continue

                    # Create base form data with dummy values
                    base_data = {i.get("name"): "test" for i in inputs if i.get("name")}
                    
                    # Test SQLi
                    for sqli in SQLI_PAYLOADS:
                        test_data = base_data.copy()
                        test_data[name] = sqli
                        
                        fuzzed_url = action
                        if method == "GET":
                            parsed = urlparse(action)
                            fuzzed_query = urlencode(test_data)
                            fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, fuzzed_query, parsed.fragment))
                            finding = await self._test_sqli(session, fuzzed_url, "GET")
                        else:
                            finding = await self._test_sqli(session, fuzzed_url, "POST", data=test_data)
                            
                        if finding:
                            findings.append(finding)
                            break

                    # Test XSS
                    for xss in XSS_PAYLOADS:
                        test_data = base_data.copy()
                        test_data[name] = xss
                        
                        fuzzed_url = action
                        if method == "GET":
                            parsed = urlparse(action)
                            fuzzed_query = urlencode(test_data)
                            fuzzed_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, fuzzed_query, parsed.fragment))
                            finding = await self._test_xss(session, fuzzed_url, xss, "GET")
                        else:
                            finding = await self._test_xss(session, fuzzed_url, xss, "POST", data=test_data)
                            
                        if finding:
                            findings.append(finding)
                            break

                tested_count += 1
                if total_tests > 0:
                    self.report_progress(5.0 + (tested_count / total_tests * 90.0), "Fuzzing forms")

        self.report_progress(100.0, "Fuzzing complete")
        
        # Deduplicate findings based on title and location
        unique_findings = []
        seen = set()
        for f in findings:
            key = f"{f.title}-{f.location}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings
