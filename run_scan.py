"""
VAPT Scanner CLI - Enterprise Multi-Scanner

Usage:
    python run_scan.py <target_url> [options]
    
Examples:
    python run_scan.py https://example.com                      # Run all scanners
    python run_scan.py https://example.com --scanner dir       # Directory scan only
    python run_scan.py https://example.com --scanner port      # Port scan only
    python run_scan.py https://example.com --scanner all       # Full scan
    python run_scan.py https://example.com --extended          # Extended wordlist
"""

import asyncio
import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from engine.scanners.dir_scanner import DirScanner, DEFAULT_WORDLIST
from engine.scanners.port_scanner import PortScanner
from engine.scanners.subdomain_scanner import SubdomainScanner
from engine.scanners.ssl_scanner import SSLScanner
from engine.scanners.endpoint_scanner import EndpointScanner
from engine.scanners.crawler_scanner import CrawlerScanner
from engine.scanners.header_scanner import HeaderScanner
from engine.scanners.fingerprint_scanner import FingerprintScanner
from engine.scanners.registry import ScannerRegistry
from engine.reports.generator import ReportGenerator

# Import scanners to register them
import engine.scanners.port_scanner
import engine.scanners.ssl_scanner
import engine.scanners.subdomain_scanner
import engine.scanners.dir_scanner
import engine.scanners.header_scanner
import engine.scanners.fingerprint_scanner
import engine.scanners.endpoint_scanner
import engine.scanners.crawler_scanner

EXTENDED_WORDLIST = DEFAULT_WORDLIST + [
    "credentials.json", ".npmrc", ".yarnrc", ".bashrc", ".bash_history",
    ".zshrc", ".profile", ".aws/credentials", ".aws/config",
    "/id_rsa", "/id_rsa.pub", "/authorized_keys",
    "phpunit.xml", "phpunit.xml.dist", ".DS_Store",
    "node_modules/.bin", "vendor/autoload.php",
    "admin.php", "admin.html", "administrator.php", "login.php",
    "wp-admin/", "wp-login/", "admin/login.php", "admin/account.php",
    "manage/", "management/", "siteadmin/", "adminarea/",
    "cpanel", "cpanel.php", "whm", "webmail/", "webmail",
    "api/", "api/v1/", "api/v2/", "api/v3/", "api/admin/",
    "api/users", "api/auth", "api/login", "api/register",
    "graphql/console", "graphiql", "altair", "voyager",
    "swagger-ui/", "swagger/index.html", "openapi.json",
    "api/documentation", "docs/api", "redoc",
    ".env.local", ".env.production", ".env.development",
    "config.php", "config.php.bak", "config.php.old",
    "configuration.php", "settings.php", "settings.json",
    "app.config", "appsettings.json", "web.config",
    "database.sql", "db.sql", "database.sqlite", "database.db",
    "backup/", "backups/", "backup/database/", "backup/files/",
    "dump.sql", "export.sql", "data.sql", "schema.sql",
    "mysql.sql", "postgres.sql", "mongodump/",
    "src/", "source/", "sourcecode/", "code/",
    ".git/", ".git/config", ".git/HEAD", ".git/index",
    ".svn/", ".hg/", ".bzr/",
    "composer.lock", "package-lock.json", "yarn.lock",
    "requirements.txt", "Pipfile", "poetry.lock",
    "test/", "tests/", "test.html", "test.php", "testing/",
    "debug/", "debug.php", "phpinfo.php", "info.php",
    "server.php", "status.php", "health.php", "ping",
    ".docker/", "docker/", "docker-compose.yaml", "docker-compose.override.yml",
    "kubernetes/", "k8s/", "helm/", "terraform/", ".terraform/",
    ".gitlab-ci.yml", ".github/workflows/", "Jenkinsfile",
    "assets/", "static/", "public/", "public/uploads/",
    "images/", "img/", "photos/", "media/",
    "downloads/", "download/", "files/", "uploads/",
    "storage/", "cache/", "tmp/", "temp/", "logs/",
    "docs/", "documentation/", "wiki/", "readme.md",
    "CHANGELOG.md", "HISTORY.md", "LICENSE.md",
    "users/", "user/", "members/", "accounts/",
    "profile/", "profiles/", "dashboard/", "home/",
    "portal/", "intranet/", "internal/",
    "error/", "errors/", "404/", "404.html", "500.html",
    "server-info/", "server-status/", "status/",
    ".well-known/acme-challenge/", ".well-known/security.txt",
    "adminpanel/", "adminconsole/", "admin1/", "administrator/",
    "Auth/", "login/", "signin/", "signup/", "register/",
    "control/", "controlpanel/", "cp/", "hosting/",
    "rest/", "rest/api/", "api/beta/", "api/dev/", "api/test/",
    "graphql.php", "graphql/api/", "v1/", "v2/", "v3/",
    "secrets/", "keys/", "certs/", "certificates/", ".keys/",
    "wallet/", "credentials/", "passwords/", "private/",
]

def print_banner():
    print("""
==============================================================
       VAPTx Enterprise Scanner v1.0
       Multi-Scanner Security Assessment Platform
==============================================================
    """)

def get_scanner(name: str, timeout: int = 10, threads: int = 50):
    scanners = {
        "dir": DirScanner, "dir_bruteforce": DirScanner, "directory": DirScanner,
        "port": PortScanner, "port_scan": PortScanner, "ports": PortScanner,
        "subdomain": SubdomainScanner, "subdomains": SubdomainScanner, "dns": SubdomainScanner,
        "ssl": SSLScanner, "ssl_scan": SSLScanner, "tls": SSLScanner,
        "endpoint": EndpointScanner, "endpoints": EndpointScanner,
        "crawler": CrawlerScanner, "crawl": CrawlerScanner,
        "headers": HeaderScanner, "header": HeaderScanner,
        "fingerprint": FingerprintScanner, "fingerprinting": FingerprintScanner,
    }
    scanner_class = scanners.get(name.lower())
    if scanner_class:
        return scanner_class(timeout=timeout, threads=threads)
    return None

def generate_report(target: str, findings, modules_run: list, scan_duration: float = 0):
    print("\n[+] Generating enterprise HTML report...")
    scan_id = f"vapt-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    created_at = datetime.now(timezone.utc).isoformat()
    
    scan_result = {
        "scan_id": scan_id, "status": "completed", "target": target,
        "modules_run": modules_run, "created_at": created_at,
        "completed_at": created_at, "duration_seconds": scan_duration,
        "findings": [f.model_dump() for f in findings], "ai_summary": None,
    }
    
    generator = ReportGenerator()
    html_content = generator.generate_html(scan_result, theme="dark")
    return html_content, scan_id

def print_summary(findings, modules_run: list):
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    type_counts = {}
    
    for f in findings:
        sev = f.severity.value.lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        f_type = f.type
        type_counts[f_type] = type_counts.get(f_type, 0) + 1
    
    print("\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    print(f"Scanners Run: {', '.join(modules_run)}")
    print("-"*60)
    print(f"  CRITICAL: {severity_counts['critical']}")
    print(f"  HIGH:     {severity_counts['high']}")
    print(f"  MEDIUM:   {severity_counts['medium']}")
    print(f"  LOW:      {severity_counts['low']}")
    print(f"  INFO:     {severity_counts['info']}")
    print(f"  TOTAL:    {len(findings)}")
    print("="*60)
    
    if type_counts:
        print("\nFINDINGS BY TYPE:")
        for ftype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"  - {ftype}: {count}")
    
    critical_findings = [f for f in findings if f.severity.value.lower() in ['critical', 'high']]
    if critical_findings:
        print("\n" + "="*60)
        print("CRITICAL & HIGH FINDINGS:")
        print("="*60)
        for f in critical_findings:
            print(f"\n[{f.severity.value.upper()}] {f.title}")
            print(f"    Type: {f.type}")
            print(f"    Location: {f.location}")
            if f.description:
                print(f"    Description: {f.description[:150]}...")
            if f.remediation:
                print(f"    Remediation: {f.remediation[:150]}...")
        print("\n" + "="*60)

async def run_scanners(target: str, scanner_names: list, timeout: int, threads: int, wordlist):
    all_findings = []
    modules_run = []
    
    scanner_suite = {
        "port": PortScanner, "ssl": SSLScanner, "subdomain": SubdomainScanner,
        "dir": DirScanner, "headers": HeaderScanner, "fingerprint": FingerprintScanner,
    }
    
    for name in scanner_names:
        scanner_class = scanner_suite.get(name.lower())
        if not scanner_class:
            print(f"[!] Unknown scanner: {name}")
            continue
            
        scanner = scanner_class(timeout=timeout, threads=threads)
        print(f"\n[+] Running {scanner.display_name}...")
        
        kwargs = {}
        if wordlist and name.lower() == 'dir':
            kwargs["wordlist"] = wordlist
        
        findings = await scanner.scan(target, **kwargs)
        all_findings.extend(findings)
        modules_run.append(scanner.name)
        
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.severity.value.lower()
            if sev in sev_counts:
                sev_counts[sev] += 1
        print(f"[*] {scanner.display_name}: C:{sev_counts['critical']} H:{sev_counts['high']} M:{sev_counts['medium']} L:{sev_counts['low']} I:{sev_counts['info']}")
    
    return all_findings, modules_run

async def main():
    parser = argparse.ArgumentParser(description="VAPTx Enterprise Multi-Scanner")
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--scanner", "-s", default="all", help="Scanners: port,ssl,subdomain,dir,headers,fingerprint,all")
    parser.add_argument("--output", "-o", default=None, help="Output HTML report file")
    parser.add_argument("--threads", type=int, default=50, help="Concurrent threads")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--extended", action="store_true", help="Use extended wordlist")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--list", action="store_true", help="List scanners")
    
    args = parser.parse_args()
    
    print_banner()
    
    if args.list:
        print("\nAvailable Scanners:")
        for s in ScannerRegistry.get_info():
            print(f"  {s['name']:20s} - {s['description']}")
        return
    
    wordlist = EXTENDED_WORDLIST if args.extended else None
    wordlist_size = len(wordlist) if wordlist else len(DEFAULT_WORDLIST)
    
    scanner_args = [s.strip() for s in args.scanner.split(',')]
    
    print(f"\n[*] Target: {args.target}")
    print(f"[*] Scanners: {args.scanner}")
    if 'dir' in scanner_args or 'all' in scanner_args:
        print(f"[*] Wordlist: {'Extended' if args.extended else 'Default'} ({wordlist_size} paths)")
    print(f"[*] Threads: {args.threads}, Timeout: {args.timeout}s")
    print("="*60)
    
    start_time = time.time()
    
    try:
        if 'all' in scanner_args:
            scanner_names = ["port", "ssl", "subdomain", "dir", "headers", "fingerprint"]
        else:
            scanner_names = scanner_args
        
        findings, modules_run = await run_scanners(
            args.target, scanner_names, args.timeout, args.threads, wordlist
        )
        
        duration = time.time() - start_time
        
        print(f"\n[+] Scan completed in {duration:.2f}s")
        print(f"[+] Total findings: {len(findings)}")
        
        print_summary(findings, modules_run)
        
        if args.json:
            out_file = args.output.replace('.html','.json') if args.output and args.output.endswith('.html') else (args.output or f"vapt_results_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json")
            with open(out_file, 'w', encoding='utf-8') as f:
                json.dump({
                    "target": args.target, "scan_duration": duration,
                    "modules_run": modules_run,
                    "findings": [f.model_dump() for f in findings]
                }, f, indent=2)
            print(f"\n[+] JSON: {out_file}")
        
        html_report, scan_id = generate_report(args.target, findings, modules_run, duration)
        
        output_file = args.output or f"VAPTx_FullScan_Report_{scan_id}.html"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        print(f"\n[+] HTML Report: {output_file}")
        
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
