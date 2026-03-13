"""
Scan orchestrator — the brain of the VAPT engine.

Coordinates scanner modules, runs them in parallel,
aggregates findings, and triggers AI analysis.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from engine.models.finding import Finding
from engine.models.scan import ScanModule, ScanResult, ScanStatus
from engine.scanners.registry import ScannerRegistry
from engine.agents.llm_service import LLMService
from engine.utils.logger import get_logger

logger = get_logger("orchestrator")

# Map ScanModule enum values to scanner registry names
MODULE_TO_SCANNER = {
    ScanModule.PORT_SCAN: "port_scan",
    ScanModule.SSL_SCAN: "ssl_scan",
    ScanModule.SUBDOMAIN: "subdomain",
    ScanModule.S3_BUCKET: "s3_bucket",
    ScanModule.FTP: "ftp",
    ScanModule.JWT: "jwt",
    ScanModule.HEADERS: "headers",
    ScanModule.COOKIES: "cookies",
    ScanModule.DIR_BRUTEFORCE: "dir_bruteforce",
    ScanModule.ENDPOINTS: "endpoints",
    ScanModule.DORKING: "dorking",
    ScanModule.CRAWLER: "crawler",
    ScanModule.FUZZER: "fuzzer",
    ScanModule.BROWSER: "browser",
    ScanModule.SSRF: "ssrf",
    ScanModule.XXE: "xxe",
    ScanModule.SESSION: "session",
    ScanModule.FINGERPRINT: "fingerprint",
    ScanModule.CORS: "cors",
    ScanModule.REDIRECT: "redirect",
    ScanModule.VORTEX: "vortex",
}

# Progress callback type
ProgressHandler = Callable[[str, float, str], None]


class ScanOrchestrator:
    """
    Orchestrates the entire scan pipeline:
    1. Creates scanner instances for requested modules
    2. Runs them concurrently with progress tracking
    3. Aggregates findings
    4. (Optional) Runs AI analysis on results
    """

    def __init__(self, llm_service: Optional[LLMService] = None):
        self.llm = llm_service or LLMService()
        self._progress_handler: Optional[ProgressHandler] = None

    def set_progress_handler(self, handler: ProgressHandler) -> None:
        """Set a handler for progress updates (module_name, percentage, message)."""
        self._progress_handler = handler

    def _report_progress(self, module: str, pct: float, msg: str) -> None:
        if self._progress_handler:
            self._progress_handler(module, pct, msg)

    async def run_scan(
        self,
        scan_id: str,
        target: str,
        modules: List[ScanModule],
        timeout: int = 10,
        threads: int = 50,
        ai_analysis: bool = True,
        jwt_token: str = "",
        auth_header: str = "",
        vortex_categories: Optional[List[str]] = None,
    ) -> ScanResult:
        """
        Execute a full scan with the requested modules.

        Returns a ScanResult with all findings.
        """
        start_time = time.time()
        created_at = datetime.now(timezone.utc).isoformat()

        logger.info(f"[{scan_id[:8]}] Starting scan of {target} with {len(modules)} modules")

        # Define attack modules that must run in Phase 2
        ATTACK_MODULES = {"fuzzer", "browser", "ssrf", "xxe", "cors", "redirect", "vortex"}

        # Create scanner instances
        discovery_scanners = []
        attack_scanners = []
        
        for module in modules:
            scanner_name = MODULE_TO_SCANNER.get(module)
            if not scanner_name:
                continue
            scanner = ScannerRegistry.create(scanner_name, timeout=timeout, threads=threads)
            if scanner:
                # Attach progress callback
                def make_callback(name):
                    return lambda pct, msg: self._report_progress(name, pct, msg)

                scanner.set_progress_callback(make_callback(scanner_name))
                if scanner_name in ATTACK_MODULES:
                    attack_scanners.append((scanner_name, scanner))
                else:
                    discovery_scanners.append((scanner_name, scanner))
            else:
                logger.warning(f"Scanner '{scanner_name}' not found in registry")

        if not discovery_scanners and not attack_scanners:
            return ScanResult(
                scan_id=scan_id,
                status=ScanStatus.FAILED,
                target=target,
                created_at=created_at,
                findings=[],
            )

        # Run all scanners concurrently
        all_findings: List[Finding] = []
        modules_run: List[str] = []
        attack_surface_data: Dict[str, Any] = {
            "internal_urls": [],
            "external_urls": [],
            "forms": [],
            "parameters": [],
            "paths": []
        }

        def merge_surface(base, new):
            if not new:
                return base
            for key, value in new.items():
                if key in base:
                    if isinstance(base[key], list) and isinstance(value, list):
                        if key in ("forms", "paths", "inputs"):
                            # Extend list for objects
                            base[key].extend(value)
                        else:
                            # Unique primitive values
                            base[key] = list(set(list(base[key]) + list(value)))
                else:
                    base[key] = value
            return base

        async def _run_scanner(name: str, scanner, surface_data=None):
            self._report_progress(name, 0.0, f"Starting {scanner.display_name}")
            kwargs: Dict[str, Any] = {}
            if name == "jwt" and jwt_token:
                kwargs["jwt_token"] = jwt_token
            if auth_header:
                kwargs["auth_header"] = auth_header
            if name == "vortex" and vortex_categories:
                kwargs["vortex_categories"] = vortex_categories
            if surface_data:
                kwargs["attack_surface"] = surface_data

            result_data = await scanner.safe_scan(target, **kwargs)
            self._report_progress(name, 100.0, f"{scanner.display_name} complete")
            
            # Crawler and DirScanner return a tuple of (findings, attack_surface)
            if name in ("crawler", "dir_bruteforce"):
                if isinstance(result_data, tuple) and len(result_data) == 2:
                    return name, result_data[0], result_data[1]
                else:
                    return name, result_data, None
            
            return name, result_data, None

        # PHASE 1: Discovery Phase
        if discovery_scanners:
            tasks = [_run_scanner(name, scanner) for name, scanner in discovery_scanners]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Discovery scanner task failed: {result}")
                    continue
                name, findings, surface = result
                modules_run.append(name)
                all_findings.extend(findings)
                if surface:
                    attack_surface_data = merge_surface(attack_surface_data, surface)

        # PHASE 2: Attack Phase
        if attack_scanners:
            tasks = [_run_scanner(name, scanner, attack_surface_data) for name, scanner in attack_scanners]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Attack scanner task failed: {result}")
                    continue
                name, findings, surface = result
                modules_run.append(name)
                all_findings.extend(findings)

        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_findings.sort(key=lambda f: severity_order.get(f.severity.value, 5))

        # Auto-enrich findings with OWASP Top 10 2025 categories
        from engine.utils.owasp_mapper import get_full_owasp_label
        for finding in all_findings:
            if finding.cwe_id and not finding.owasp_category:
                owasp_label = get_full_owasp_label(finding.cwe_id)
                if owasp_label:
                    finding.owasp_category = owasp_label

        # Generate AI summary if enabled
        ai_summary = None
        if ai_analysis and self.llm.is_available and all_findings:
            self._report_progress("ai_analysis", 0.0, "Running AI analysis...")
            try:
                findings_dicts = [f.model_dump() for f in all_findings]
                ai_summary = await self.llm.analyze_findings(findings_dicts, target)
                self._report_progress("ai_analysis", 100.0, "AI analysis complete")
            except Exception as exc:
                logger.error(f"AI analysis failed: {exc}")

        elapsed = time.time() - start_time
        completed_at = datetime.now(timezone.utc).isoformat()

        logger.info(
            f"[{scan_id[:8]}] Scan complete — "
            f"{len(all_findings)} findings in {elapsed:.1f}s"
        )

        return ScanResult(
            scan_id=scan_id,
            status=ScanStatus.COMPLETED,
            target=target,
            modules_run=modules_run,
            created_at=created_at,
            completed_at=completed_at,
            duration_seconds=round(elapsed, 2),
            findings=[f.model_dump() for f in all_findings],
            ai_summary=ai_summary,
            attack_surface=attack_surface_data,
        )
