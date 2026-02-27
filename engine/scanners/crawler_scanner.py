"""
Web Crawler and Attack Surface Mapper.

Recursively spiders the application to map out all discovered:
- URLs and Directories
- External Links
- Input Forms and their expected parameters
- URL query parameters
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import normalize_target


@ScannerRegistry.register
class CrawlerScanner(BaseScanner):
    
    # Internal state for the crawler
    _visited: Set[str] = set()
    _attack_surface: Dict[str, Any] = {
        "internal_urls": set(),
        "external_urls": set(),
        "forms": [],
        "parameters": set()
    }
    
    @property
    def name(self) -> str:
        return "crawler"

    @property
    def display_name(self) -> str:
        return "Attack Surface Mapper"

    @property
    def description(self) -> str:
        return "Recursively maps internal URLs, forms, and input parameters"

    def _is_internal(self, base_url: str, url: str) -> bool:
        """Check if a URL belongs to the same target domain."""
        base_domain = urlparse(base_url).netloc
        target_domain = urlparse(url).netloc
        return base_domain == target_domain or target_domain == ""

    async def _crawl_url(self, session: aiohttp.ClientSession, base_url: str, current_url: str, depth: int, max_depth: int, max_pages: int) -> None:
        """Crawl a single URL and extract links and forms."""
        if depth > max_depth or current_url in self._visited or len(self._visited) >= max_pages:
            return

        self._visited.add(current_url)
        
        # Dynamic progress reporting between 10% and 90%
        progress = 10.0 + (len(self._visited) / max_pages * 80.0)
        self.report_progress(progress, f"Crawling: {len(self._visited)}/{max_pages} pages")

        try:
            # We only crawl HTML pages
            async with session.get(current_url, ssl=False, allow_redirects=True) as resp:
                if resp.status != 200 or "text/html" not in resp.headers.get("Content-Type", ""):
                    return
                html = await resp.text()
        except Exception:
            return

        soup = BeautifulSoup(html, "html.parser")

        # 1. Extract Links (<a>)
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if href.startswith(("javascript:", "mailto:", "tel:")):
                continue
                
            full_url = urljoin(current_url, href)
            
            # Extract query parameters
            parsed = urlparse(full_url)
            if parsed.query:
                for param in parsed.query.split("&"):
                    if "=" in param:
                        self._attack_surface["parameters"].add(param.split("=")[0])

            # Strip fragments and queries for the visited set to avoid infinite duplicate loops
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            if self._is_internal(base_url, full_url):
                self._attack_surface["internal_urls"].add(full_url)
                if clean_url not in self._visited and len(self._visited) < max_pages:
                    # Recursively crawl
                    await self._crawl_url(session, base_url, clean_url, depth + 1, max_depth, max_pages)
            else:
                self._attack_surface["external_urls"].add(full_url)

        # 2. Extract Forms (<form>)
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            full_action = urljoin(current_url, action)
            
            inputs = []
            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name")
                if name:
                    inputs.append({
                        "name": name,
                        "type": inp.get("type", "text")
                    })
                    self._attack_surface["parameters"].add(name)
            
            form_data = {
                "action": full_action,
                "method": method,
                "inputs": inputs,
                "found_on": current_url
            }
            # Only add if we haven't seen this exact form yet
            if form_data not in self._attack_surface["forms"]:
                self._attack_surface["forms"].append(form_data)


    async def scan(self, target: str, **kwargs: Any) -> Tuple[List[Finding], Dict[str, Any]]:
        """
        Custom scan signature: The crawler returns Findings AND the mapped Attack Surface data.
        """
        base_url = normalize_target(target)
        
        # Reset state for this scan run
        self._visited = set()
        self._attack_surface = {
            "internal_urls": set(),
            "external_urls": set(),
            "forms": [],
            "parameters": set()
        }
        
        # Configuration
        max_depth = kwargs.get("max_depth", 3)
        max_pages = kwargs.get("max_pages", 50)  # Hard limit to prevent infinite scanning on huge sites
        timeout_val = aiohttp.ClientTimeout(total=self.timeout)

        self.report_progress(10.0, f"Starting crawl (Max Depth: {max_depth}, Limit: {max_pages})")

        async with aiohttp.ClientSession(timeout=timeout_val, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}) as session:
            await self._crawl_url(session, base_url, base_url, depth=1, max_depth=max_depth, max_pages=max_pages)

        self.report_progress(90.0, "Crawl complete. Analyzing surface data.")

        # Prepare findings based on the crawl
        findings = []
        
        # Finding: Attack Surface Mapped
        total_urls = len(self._attack_surface["internal_urls"])
        total_forms = len(self._attack_surface["forms"])
        total_params = len(self._attack_surface["parameters"])
        
        findings.append(Finding(
            scanner=self.name,
            type="Attack Surface Mapped",
            severity=Severity.INFO,
            title=f"Mapped {total_urls} URLs, {total_forms} forms, {total_params} parameters",
            description=(
                "The web crawler successfully mapped the application's attack surface. "
                "This mapping discovers hidden inputs and endpoints that are critical for injection testing."
            ),
            evidence=f"Discovered {total_params} unique input parameters across the site.",
            location=base_url
        ))

        # Warning Finding: Forms transmitting over HTTP (if base_url is HTTP)
        if base_url.startswith("http://") and total_forms > 0:
            findings.append(Finding(
                scanner=self.name,
                type="Insecure Form Transmission",
                severity=Severity.MEDIUM,
                title="Forms discovered on unencrypted connection (HTTP)",
                description="The crawler found HTML forms submitting data over HTTP. Credentials or sensitive data submitted through these forms can be intercepted.",
                remediation="Force HTTPS redirect on all pages containing forms.",
                cwe_id="CWE-319"
            ))

        self.report_progress(100.0, "Attack surface mapping complete")
        
        # Convert sets to lists for JSON serialization before returning
        serialized_surface = {
            "internal_urls": list(self._attack_surface["internal_urls"]),
            "external_urls": list(self._attack_surface["external_urls"]),
            "forms": self._attack_surface["forms"],
            "parameters": list(self._attack_surface["parameters"])
        }
        
        return findings, serialized_surface
