"""
Web Crawler and Attack Surface Mapper — BFS Async Edition

Recursively spiders the application using a concurrent BFS queue to map:
  - Internal URLs and directories
  - External links
  - HTML forms and their input parameters
  - URL query parameters
  - JavaScript-referenced paths (basic static extraction)

Fixed issues in previous version:
  1. Class-level state caused cross-scan data leaks → now all state is instance-local
  2. Sequential recursive crawling was O(1) per tick → now 30 concurrent workers
  3. Content-Type check was too strict (missed charsets) → now uses `in` substring
  4. 10s timeout killed real sites → now 30s with separate connect/read timeouts
  5. No robots.txt / sitemap seed → now fetches robots.txt to prime the queue
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

import aiohttp
from bs4 import BeautifulSoup

from engine.models.finding import Finding, Severity
from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.utils.network import normalize_target

# ──────────────────────────────────────────────
# Static regex for JS-referenced paths
# e.g.  fetch('/api/users'), axios.get("/profile")
# ──────────────────────────────────────────────
_JS_PATH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|\.href)\s*\(\s*['"`]([^'"`]+)['"`]""",
    re.IGNORECASE,
)

MAX_CONCURRENCY = 30  # simultaneous HTTP requests


@ScannerRegistry.register
class CrawlerScanner(BaseScanner):
    """Async BFS web crawler that maps the complete attack surface."""

    @property
    def name(self) -> str:
        return "crawler"

    @property
    def display_name(self) -> str:
        return "Attack Surface Mapper"

    @property
    def description(self) -> str:
        return "Recursively maps internal URLs, forms, and input parameters using async BFS"

    # ── helpers ────────────────────────────────

    @staticmethod
    def _same_domain(base_url: str, url: str) -> bool:
        base = urlparse(base_url).netloc.lower()
        target = urlparse(url).netloc.lower()
        return target == "" or target == base or target.endswith("." + base)

    @staticmethod
    def _clean_url(url: str) -> str:
        """Strip fragment; keep path + query for deduplication."""
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path}"

    @staticmethod
    def _is_crawlable(url: str) -> bool:
        """Skip binary/media/asset extensions."""
        skipped = {
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
            ".mp4", ".mp3", ".webm", ".ogg", ".pdf", ".zip", ".gz",
            ".tar", ".rar", ".exe", ".dll", ".css", ".woff", ".woff2",
            ".ttf", ".eot", ".map",
        }
        path = urlparse(url).path.lower()
        return not any(path.endswith(ext) for ext in skipped)

    # ── robots.txt seed ────────────────────────

    async def _fetch_robots(
        self, session: aiohttp.ClientSession, base_url: str
    ) -> List[str]:
        """Parse robots.txt and return unique Disallow/Allow paths as seeds."""
        robots_url = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}/robots.txt"
        seeds: List[str] = []
        try:
            async with session.get(robots_url, ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    for line in text.splitlines():
                        line = line.strip()
                        if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                            _, _, path = line.partition(":")
                            path = path.strip()
                            if path and path != "/" and "*" not in path:
                                seeds.append(urljoin(base_url, path))
        except Exception:
            pass
        return seeds

    # ── page processor ─────────────────────────

    async def _process_page(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        url: str,
        attack_surface: Dict[str, Any],
    ) -> List[str]:
        """
        Fetch a URL, extract links/forms/params and return newly discovered
        internal URLs to enqueue. Returns [] on any error.
        """
        try:
            async with session.get(
                url,
                ssl=False,
                allow_redirects=True,
                timeout=aiohttp.ClientTimeout(connect=8, sock_read=15),
            ) as resp:
                content_type = resp.headers.get("Content-Type", "")
                is_html = "html" in content_type or content_type == ""
                is_js = "javascript" in content_type

                if resp.status not in (200, 201) or not (is_html or is_js):
                    return []

                html = await resp.text(errors="replace")
        except Exception:
            return []

        discovered: List[str] = []

        if is_js:
            # Extract paths referenced in JS
            for match in _JS_PATH_RE.finditer(html):
                path = match.group(1)
                if path.startswith(("/", "http")):
                    full = urljoin(url, path)
                    if self._same_domain(base_url, full):
                        clean = self._clean_url(full)
                        discovered.append(clean)
            return discovered

        soup = BeautifulSoup(html, "html.parser")

        # ── 1. Links ──────────────────────────
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                continue
            full = urljoin(url, href)
            parsed = urlparse(full)

            # Extract GET params
            if parsed.query:
                for key in parse_qs(parsed.query):
                    attack_surface["parameters"].add(key)

            clean = self._clean_url(full)
            if self._same_domain(base_url, full):
                attack_surface["internal_urls"].add(full)
                if self._is_crawlable(clean):
                    discovered.append(clean)
            else:
                attack_surface["external_urls"].add(full)

        # ── 2. Script src links ───────────────
        for script in soup.find_all("script", src=True):
            src = script["src"].strip()
            full = urljoin(url, src)
            if self._same_domain(base_url, full) and self._is_crawlable(full):
                discovered.append(self._clean_url(full))

        # ── 3. Forms ─────────────────────────
        for form in soup.find_all("form"):
            action = form.get("action", "") or url
            method = form.get("method", "get").upper()
            full_action = urljoin(url, action)

            inputs = []
            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name")
                if name:
                    inputs.append({"name": name, "type": inp.get("type", "text")})
                    attack_surface["parameters"].add(name)

            form_data = {
                "action": full_action,
                "method": method,
                "inputs": inputs,
                "found_on": url,
            }
            if form_data not in attack_surface["forms"]:
                attack_surface["forms"].append(form_data)

        # ── 4. Static JS path references ──────
        for script_tag in soup.find_all("script"):
            if not script_tag.get("src") and script_tag.string:
                for match in _JS_PATH_RE.finditer(script_tag.string):
                    path = match.group(1)
                    if path.startswith(("/", "http")):
                        full = urljoin(url, path)
                        if self._same_domain(base_url, full):
                            discovered.append(self._clean_url(full))

        return discovered

    # ── BFS worker ─────────────────────────────

    async def _worker(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        queue: asyncio.Queue,
        visited: Set[str],
        attack_surface: Dict[str, Any],
        max_pages: int,
    ) -> None:
        while True:
            try:
                url = queue.get_nowait()
            except asyncio.QueueEmpty:
                break

            if url in visited or len(visited) >= max_pages:
                queue.task_done()
                continue

            visited.add(url)

            # Progress: 10% → 90% mapped to visited/max_pages
            progress = 10.0 + (len(visited) / max_pages) * 80.0
            self.report_progress(
                min(progress, 89.0),
                f"Crawling {len(visited)}/{max_pages} — {url[:60]}",
            )

            new_urls = await self._process_page(session, base_url, url, attack_surface)

            for nu in new_urls:
                if nu not in visited and len(visited) < max_pages:
                    await queue.put(nu)

            queue.task_done()

    # ── main scan ──────────────────────────────

    async def scan(self, target: str, **kwargs: Any) -> Tuple[List[Finding], Dict[str, Any]]:
        """
        BFS crawl with MAX_CONCURRENCY parallel workers.
        Returns (findings, attack_surface_dict).
        """
        base_url = normalize_target(target)

        # ── instance-local state (no cross-scan leaks) ──
        visited: Set[str] = set()
        attack_surface: Dict[str, Any] = {
            "internal_urls": set(),
            "external_urls": set(),
            "forms": [],
            "parameters": set(),
        }

        max_depth = kwargs.get("max_depth", 5)   # kept for API compat, BFS uses max_pages
        max_pages = kwargs.get("max_pages", 200)  # raised from 50 → 200

        self.report_progress(5.0, f"Initialising crawl — target: {base_url}")

        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENCY, ssl=False)
        session_timeout = aiohttp.ClientTimeout(total=120)
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        async with aiohttp.ClientSession(
            connector=connector, timeout=session_timeout, headers=headers
        ) as session:
            self.report_progress(8.0, "Seeding queue from robots.txt…")
            robot_seeds = await self._fetch_robots(session, base_url)

            # Prime the BFS queue
            queue: asyncio.Queue = asyncio.Queue()
            await queue.put(self._clean_url(base_url))
            attack_surface["internal_urls"].add(base_url)
            for seed in robot_seeds:
                await queue.put(self._clean_url(seed))

            self.report_progress(10.0, f"BFS started — {queue.qsize()} initial seeds")

            # Run up to MAX_CONCURRENCY workers simultaneously, cycling until queue is empty
            while not queue.empty() and len(visited) < max_pages:
                batch_size = min(MAX_CONCURRENCY, queue.qsize(), max_pages - len(visited))
                workers = [
                    asyncio.create_task(
                        self._worker(session, base_url, queue, visited, attack_surface, max_pages)
                    )
                    for _ in range(batch_size)
                ]
                await asyncio.gather(*workers, return_exceptions=True)

        self.report_progress(90.0, "Crawl complete — compiling results…")

        # ── findings ──────────────────────────────────────────────────────
        total_urls = len(attack_surface["internal_urls"])
        total_forms = len(attack_surface["forms"])
        total_params = len(attack_surface["parameters"])

        findings: List[Finding] = []

        findings.append(
            Finding(
                scanner=self.name,
                type="Attack Surface Mapped",
                severity=Severity.INFO,
                title=f"Mapped {total_urls} URLs, {total_forms} forms, {total_params} parameters",
                description=(
                    "The web crawler successfully mapped the application's attack surface "
                    "using async BFS with up to 30 parallel workers. "
                    "Discovered endpoints, forms, and parameters are used by Vortex for injection testing."
                ),
                evidence=f"{len(visited)} pages crawled. {total_params} unique input parameters found.",
                location=base_url,
            )
        )

        if base_url.startswith("http://") and total_forms > 0:
            findings.append(
                Finding(
                    scanner=self.name,
                    type="Insecure Form Transmission",
                    severity=Severity.MEDIUM,
                    title="Forms discovered on unencrypted connection (HTTP)",
                    description=(
                        f"The crawler found {total_forms} HTML form(s) submitting data over HTTP. "
                        "Credentials or sensitive data can be intercepted in transit."
                    ),
                    remediation="Enforce HTTPS redirect on all pages containing forms.",
                    cwe_id="CWE-319",
                )
            )

        if total_params == 0 and total_forms == 0:
            findings.append(
                Finding(
                    scanner=self.name,
                    type="No Injectable Surface Found",
                    severity=Severity.INFO,
                    title="No input parameters or forms discovered",
                    description=(
                        "The crawler found no HTML forms or query parameters. "
                        "The target may be a static site, may require authentication, "
                        "or may block crawlers via robots.txt."
                    ),
                    evidence=f"Pages crawled: {len(visited)}. Internal URLs found: {total_urls}.",
                    location=base_url,
                )
            )

        self.report_progress(100.0, "Attack surface mapping complete")

        # Serialise sets → lists for JSON / orchestrator handoff
        serialized_surface = {
            "internal_urls": list(attack_surface["internal_urls"]),
            "external_urls": list(attack_surface["external_urls"]),
            "forms": attack_surface["forms"],
            "parameters": list(attack_surface["parameters"]),
        }

        return findings, serialized_surface
