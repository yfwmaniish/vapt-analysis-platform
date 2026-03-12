import os
import sys
import argparse
import asyncio
import aiohttp
from typing import List, Dict, Optional

from engine.models.finding import Finding, Severity

# Path to the payloads repository
PAYLOADS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "payloads")

class VortexExplorer:
    def __init__(self):
        self.categories = self._get_categories()

    def _get_categories(self) -> List[str]:
        """List all vulnerability categories in the payloads directory."""
        if not os.path.exists(PAYLOADS_DIR):
            return []
        return [d for d in os.listdir(PAYLOADS_DIR) if os.path.isdir(os.path.join(PAYLOADS_DIR, d)) and not d.startswith('.')]

    def list_categories(self):
        print("\n=== Vortex Explorer: Vulnerability Categories ===")
        for i, category in enumerate(sorted(self.categories), 1):
            print(f"{i:2}. {category}")
        print("================================================\n")

    def get_payload_files(self, category: str) -> List[str]:
        """Find all .txt or .md files in the selected category, prioritizing Intruder/ folder if it exists."""
        cat_path = os.path.join(PAYLOADS_DIR, category)
        intruder_path = os.path.join(cat_path, "Intruder")
        
        search_path = intruder_path if os.path.exists(intruder_path) else cat_path
        payload_files = []
        
        for root, _, files in os.walk(search_path):
            for file in files:
                if file.endswith(('.txt', '.md', '.py', '.sh')):
                    payload_files.append(os.path.join(root, file))
        return payload_files

    def _clean_payload(self, raw_line: str) -> Optional[str]:
        """Basic cleaning of payloads, especially from .md files."""
        line = raw_line.strip()
        if not line or line.startswith(('#', '*', '-', '`')):
            return None
        # Ignore common descriptive words often found in .md files
        if any(word in line.lower() for word in ["example:", "requirements:", "payload:", "references:"]):
            return None
        return line

    async def test_single_payload(self, session: aiohttp.ClientSession, target: str, payload: str, category: str, semaphore: asyncio.Semaphore) -> Optional[Finding]:
        async with semaphore:
            test_url = target.replace("FUZZ", payload) if "FUZZ" in target else f"{target}/{payload}"
            if not test_url.startswith(('http://', 'https://')):
                test_url = 'http://' + test_url
                
            try:
                async with session.get(test_url, timeout=10) as response:
                    text = await response.text()
                    
                    found_type = None
                    severity = Severity.INFO
                    
                    # Specialized Detection
                    if "SQL Injection" in category:
                        sql_errors = ["mysql_fetch_array", "SQL syntax", "PostgreSQL", "error in your SQL syntax", "warning: mysql"]
                        if any(err.lower() in text.lower() for err in sql_errors):
                            found_type = "SQL Injection"
                            severity = Severity.CRITICAL
                    
                    elif "XSS Injection" in category:
                        # Improved: Check if payload is reflected UNENCODED
                        if payload in text:
                            # Higher severity for actual script execution attempts
                            if any(x in payload.lower() for x in ["<script", "alert(", "onload=", "onerror=", "javascript:"]):
                                found_type = "Reflected XSS (Executable)"
                                severity = Severity.HIGH
                            elif any(x in payload for x in ["<", ">"]):
                                found_type = "Reflected Input (HTML Tags)"
                                severity = Severity.MEDIUM
                            elif len(payload) > 4:
                                found_type = "Reflected Input"
                                severity = Severity.LOW
                    
                    elif "Server Side Request Forgery" in category:
                        if response.status == 200 and ("localhost" in payload or "127.0.0.1" in payload):
                            found_type = "Potential SSRF"
                            severity = Severity.HIGH
                    
                    if found_type:
                        print(f"    [!] {found_type.upper()}: {test_url}")
                        return Finding(
                            scanner="vortex",
                            type=found_type,
                            severity=severity,
                            title=f"{found_type} via Vortex Explorer",
                            description=f"Automated payload testing detected a potential {found_type} vulnerability.",
                            evidence=f"Payload: {payload}\nURL: {test_url}",
                            location=test_url,
                            remediation="Sanitize input and use parameterized queries/output encoding.",
                            owasp_category="A03: Injection"
                        )
            except Exception:
                pass
            return None

    async def execute_payloads(self, target: str, payload_file: str, category: str) -> List[Finding]:
        """Concurrent execution logic based on vulnerability category."""
        all_findings = []
        print(f"[*] Testing {category} from: {os.path.basename(payload_file)}")
        try:
            with open(payload_file, 'r', encoding='utf-8', errors='ignore') as f:
                payloads = [p for p in (self._clean_payload(line) for line in f) if p]

            if not payloads:
                return []

            semaphore = asyncio.Semaphore(20)
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                tasks = [self.test_single_payload(session, target, p, category, semaphore) for p in payloads]
                results = await asyncio.gather(*tasks)
                
            all_findings = [r for r in results if r]
            success_count = sum(1 for r in results if r is not None)
            print(f"[+] Finished: {len(all_findings)} findings, {success_count} probes successful.")
            return all_findings
        except Exception as e:
            print(f"[-] Error reading payloads: {e}")
            return []

async def run_vortex(target: str, category_input: str = None) -> List[Finding]:
    """Library entry point for run_scan.py"""
    explorer = VortexExplorer()
    if not category_input:
        return []
    
    # Resolve category name if it's a number
    category_name = None
    if category_input.isdigit():
        idx = int(category_input) - 1
        if 0 <= idx < len(explorer.categories):
            category_name = sorted(explorer.categories)[idx]
    else:
        # Try to match by name
        for cat in explorer.categories:
            if category_input.lower() in cat.lower():
                category_name = cat
                break
    
    if not category_name:
        print(f"[-] Vortex: Unknown category '{category_input}'")
        return []
    
    print(f"[*] Vortex: Deep Dive into '{category_name}'...")
    payload_files = explorer.get_payload_files(category_name)
    all_findings = []
    for pf in payload_files:
        findings = await explorer.execute_payloads(target, pf, category_name)
        all_findings.extend(findings)
    return all_findings

def main():
    parser = argparse.ArgumentParser(description="Vortex Explorer: PayloadsAllTheThings Deep Dive")
    parser.add_argument("--list", action="store_true", help="List available vulnerability categories")
    parser.add_argument("--category", type=str, help="Specify category (number or name)")
    parser.add_argument("--target", type=str, help="Target URL (e.g., http://example.com?id=FUZZ)")
    
    args = parser.parse_args()
    explorer = VortexExplorer()

    if args.list:
        explorer.list_categories()
        return

    category_name = None
    if args.category:
        if args.category.isdigit():
            idx = int(args.category) - 1
            if 0 <= idx < len(explorer.categories):
                category_name = sorted(explorer.categories)[idx]
        else:
            for cat in explorer.categories:
                if args.category.lower() in cat.lower():
                    category_name = cat
                    break
    
    if not category_name:
        explorer.list_categories()
        try:
            category_input = input("Enter Category Number or Name (e.g. 49 for SQLi): ").strip()
            if category_input.isdigit():
                idx = int(category_input) - 1
                if 0 <= idx < len(explorer.categories):
                    category_name = sorted(explorer.categories)[idx]
            else:
                for cat in explorer.categories:
                    if category_input.lower() in cat.lower():
                        category_name = cat
                        break
        except EOFError:
            return
    
    if not category_name:
        print("[-] Selection cancelled or invalid.")
        return

    if not args.target:
        try:
            args.target = input(f"Enter target URL for {category_name} (use FUZZ for injection point): ").strip()
        except EOFError:
            return
        if not args.target:
            print("[-] Target required.")
            return

    # Execution loop
    payload_files = explorer.get_payload_files(category_name)
    loop = asyncio.get_event_loop()
    all_findings = []
    for pf in payload_files:
        findings = loop.run_until_complete(explorer.execute_payloads(args.target, pf, category_name))
        all_findings.extend(findings)
    
    print(f"\n[+] Vortex Deep Dive Complete. Total Potential Findings: {len(all_findings)}")

if __name__ == "__main__":
    main()
