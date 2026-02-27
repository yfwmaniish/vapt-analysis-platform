import asyncio
import re
from typing import Any
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from playwright.async_api import async_playwright
import traceback

from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.models.finding import Finding, Severity

@ScannerRegistry.register
class BrowserScanner(BaseScanner):
    """
    Headless Browser Scanner using Playwright.
    Dynamically executes JS to detect DOM XSS, outdated libraries, and client-side flaws.
    Runs in the Attack Phase, utilizing Attack Surface data.
    """
    
    name = "browser"
    description = "Headless Browser (Playwright) for DOM XSS and JS analysis"
    
    @property
    def display_name(self) -> str:
        return "Headless Browser Analyzer"
    
    async def scan(self, target: str, **kwargs: Any) -> list[Finding]:
        findings = []
        attack_surface = kwargs.get("attack_surface", {})
        
        # Extract internal URLs. If none, just scan the main target.
        urls_to_scan = attack_surface.get("internal_urls", [])
        if not urls_to_scan:
            urls_to_scan = [target]
            
        # Limit to 5 URLs to keep the scan fast
        urls_to_scan = list(set(urls_to_scan))[:5]
        
        # DOM XSS payload definition
        xss_payload = "vltro\"><script>alert('VLTRO_DOM_XSS')</script>"
        
        # Prepare URLs with payloads for parameters, if any
        test_urls = []
        for url in urls_to_scan:
            parsed = urlparse(url)
            params = parse_qsl(parsed.query)
            if params:
                # Inject payload into all params
                injected_params = [(k, xss_payload) for k, v in params]
                new_query = urlencode(injected_params)
                test_url = urlunparse(parsed._replace(query=new_query))
                test_urls.append(test_url)
            else:
                test_urls.append(url)
                # Also try appending a fake parameter
                test_urls.append(f"{url}?vltro_test={xss_payload}")
                
        # Deduplicate and limit total URLs
        test_urls = list(set(test_urls))[:10]
        
        if self._progress_callback:
            self.report_progress(5.0, f"Initializing headless browser for {len(test_urls)} pages")
            
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(ignore_https_errors=True)
                
                for idx, t_url in enumerate(test_urls):
                    try:
                        page = await context.new_page()
                        
                        # Set up a dialog handler to catch DOM XSS execution
                        dom_xss_found = False
                        
                        async def handle_dialog(dialog):
                            nonlocal dom_xss_found
                            if dialog.message == "VLTRO_DOM_XSS":
                                dom_xss_found = True
                            await dialog.accept()
                            
                        page.on("dialog", handle_dialog)
                        
                        # Set a fast timeout (15s) so we don't hang on bad pages
                        await page.goto(t_url, wait_until="domcontentloaded", timeout=15000)
                        
                        # Allow a tiny bit of time for JS execution
                        await asyncio.sleep(1)
                        
                        if dom_xss_found:
                            findings.append(Finding(
                                title="DOM Cross-Site Scripting (XSS) Executed",
                                description="A DOM-based XSS payload was successfully executed by the browser via URL parameters.",
                                severity=Severity.HIGH,
                                location=t_url,
                                mitigation="Ensure all user-controlled input read from the DOM is properly sanitized before being written to the page or executed.",
                                evidence=f"Payload `{xss_payload}` triggered a JavaScript alert."
                            ))
                            
                        # Detect outdated JS Libraries (e.g., jQuery)
                        jquery_version = await page.evaluate("() => window.jQuery ? window.jQuery.fn.jquery : null")
                        if jquery_version:
                            # Simple check, real world would use a CVE database
                            if jquery_version.startswith("1.") or jquery_version.startswith("2."):
                                findings.append(Finding(
                                    title=f"Outdated jQuery Library Detected ({jquery_version})",
                                    description="An outdated and potentially vulnerable version of jQuery is in use.",
                                    severity=Severity.LOW,
                                    location=t_url,
                                    mitigation="Update jQuery to the latest stable 3.x release.",
                                    evidence=f"window.jQuery.fn.jquery = {jquery_version}"
                                ))
                                
                        await page.close()
                        
                    except Exception as e:
                        # Timeout or navigation errors are common, we skip those
                        pass
                        
                    if self._progress_callback:
                        progress = 5.0 + ((idx + 1) / len(test_urls)) * 90.0
                        self.report_progress(progress, f"Analyzed page {idx+1}/{len(test_urls)}")
                        
                await browser.close()
                
        except Exception as e:
            findings.append(Finding(
                title="Browser Execution Error",
                description="The headless browser encountered a critical error during initialization or execution.",
                severity=Severity.INFO,
                location=target,
                mitigation="Check server memory and Playwright dependency installation.",
                evidence=str(e) + "\n" + traceback.format_exc()
            ))

        if self._progress_callback:
             self.report_progress(100.0, "Headless Browser analysis complete")
             
        # Optional deduplication of library versions
        unique_findings = []
        seen_titles = set()
        for f in findings:
            if f.title not in seen_titles:
                seen_titles.add(f.title)
                unique_findings.append(f)
                
        return unique_findings
