import asyncio
import aiohttp
from typing import Any, List
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.models.finding import Finding, Severity


@ScannerRegistry.register
class SSRFScanner(BaseScanner):
    """
    Server-Side Request Forgery (SSRF) Scanner.
    Injects loopback and cloud metadata payloads into discovered URL parameters.
    Runs in the Attack Phase, utilizing Attack Surface data.
    """
    
    name = "ssrf"
    description = "Tests parameters for Server-Side Request Forgery vulnerabilities."
    
    @property
    def display_name(self) -> str:
        return "SSRF Scanner"
        
    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        findings = []
        attack_surface = kwargs.get("attack_surface", {})
        
        # Only extract URLs that had parameters, since SSRF usually targets endpoints fetching data
        urls_to_scan = attack_surface.get("internal_urls", [])
        if not urls_to_scan:
            urls_to_scan = [target]
            
        urls_with_params = [u for u in urls_to_scan if "?" in u]
        if not urls_with_params and urls_to_scan:
             urls_with_params = urls_to_scan[:5] # Fallback to base URLs
             
        urls_to_scan = list(set(urls_with_params))[:10]
        
        # Common SSRF Payloads
        ssrf_payloads = [
            "http://127.0.0.1:80",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/", # AWS metadata
            "file:///etc/passwd"
        ]
        
        target_domain = urlparse(target).netloc
        
        if self._progress_callback:
            self.report_progress(5.0, f"Testing {len(urls_to_scan)} URLs for SSRF")
            
        async with aiohttp.ClientSession() as session:
            for idx, url in enumerate(urls_to_scan):
                parsed = urlparse(url)
                params = parse_qsl(parsed.query)
                
                if not params:
                    # Append a fake url param to test
                    params = [("url", "")]
                    
                for payload in ssrf_payloads:
                    for i, (k, v) in enumerate(params):
                        # Create a new parameter list with the injected payload
                        test_params = list(params)
                        test_params[i] = (k, payload)
                        new_query = urlencode(test_params)
                        test_url = urlunparse(parsed._replace(query=new_query))
                        
                        try:
                            # Use a very short timeout since we're often waiting for network errors/timeouts
                            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as response:
                                content = await response.text()
                                
                                # Analyze Response for SSRF markers
                                if "root:x:0:0" in content:
                                    findings.append(Finding(
                                        title=f"Local File Inclusion / Local SSRF via {k}",
                                        description=f"The parameter '{k}' allows reading local system files.",
                                        severity=Severity.HIGH,
                                        location=test_url,
                                        mitigation="Validate and sanitize all URLs processed by the server. Use an allowlist approach.",
                                        evidence="Found 'root:x:0:0' in the response body."
                                    ))
                                elif "ami-id" in content or "instance-id" in content:
                                    findings.append(Finding(
                                        title=f"Cloud Metadata SSRF Detected via {k}",
                                        description=f"The parameter '{k}' successfully retrieved cloud infrastructure metadata.",
                                        severity=Severity.CRITICAL,
                                        location=test_url,
                                        mitigation="Block requests to 169.254.169.254. Enforce IMDSv2 on AWS environments.",
                                        evidence="Found metadata keys like 'ami-id' or 'instance-id' in response."
                                    ))
                                # Blind SSRF detection (heuristics based on response times or arbitrary specific text)
                                # is harder without an out-of-band collaborator (like Burp Collaborator).
                                # We stick to direct response reflection here.
                                
                        except asyncio.TimeoutError:
                            # A timeout when hitting 127.0.0.1 could imply the server tried to connect and hung, 
                            # indicating a potential blind SSRF.
                            if "127.0.0.1" in payload:
                                findings.append(Finding(
                                    title=f"Potential Blind SSRF (Timeout) via {k}",
                                    description=f"The parameter '{k}' caused a timeout when injected with a loopback address, suggesting the server attempted connection.",
                                    severity=Severity.LOW,
                                    location=test_url,
                                    mitigation="Ensure server-side requests only target allowed internal domains.",
                                    evidence=f"Request to {test_url} timed out."
                                ))
                        except aiohttp.ClientError:
                            pass # Connection refused by target, ignore
                            
                if self._progress_callback:
                    progress = 5.0 + ((idx + 1) / len(urls_to_scan)) * 95.0
                    self.report_progress(progress, f"Analyzed {idx+1}/{len(urls_to_scan)} URLs")
                    
        # Deduplicate
        unique_findings = []
        seen = set()
        for f in findings:
            key = f.title + f.location
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
                
        return unique_findings
