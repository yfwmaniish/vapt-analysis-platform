
import asyncio
import os
import sys
from datetime import datetime
from engine.reports.generator import ReportGenerator
from engine.models.scan import ScanResult, ScanStatus, ScanRequest
from engine.models.finding import Finding

async def test_report():
    print("Testing Report Generation with Attack Surface Inventory...")
    
    # Mock Attack Surface Data
    attack_surface = {
        "paths": [
            {"path": "/admin", "status": 200, "type": "directory"},
            {"path": "/config.php", "status": 403, "type": "file"},
            {"path": "/uploads/", "status": 200, "type": "directory"},
            {"path": "/.env", "status": 404, "type": "file"},
            {"path": "/api/v1/users", "status": 200, "type": "api"}
        ],
        "forms": [
            {"action": "/login", "method": "POST", "inputs": ["username", "password", "csrf_token"]},
            {"action": "/search", "method": "GET", "inputs": ["q", "page"]}
        ],
        "internal_urls": ["https://example.com/about", "https://example.com/contact"],
        "external_urls": ["https://google.com", "https://cdn.example.com/js/app.js"]
    }
    
    # Mock Findings
    findings = [
        Finding(
            scanner="DirScanner",
            type="Sensitive File",
            severity="high",
            title="Exposed Configuration File",
            description="The file /config.php was found and might contain credentials.",
            location="https://example.com/config.php",
            cwe_id="CWE-200"
        ),
        Finding(
            scanner="HeaderScanner",
            type="Missing Security Header",
            severity="low",
            title="Missing HSTS Header",
            description="The HSTS header is missing.",
            location="https://example.com",
            cwe_id="CWE-1027"
        )
    ]
    
    # Mock Scan Result
    result = ScanResult(
        scan_id="test-scan-123",
        target="https://example.com",
        status=ScanStatus.COMPLETED,
        findings=findings,
        attack_surface=attack_surface,
        created_at=datetime.now().isoformat(),
        completed_at=datetime.now().isoformat(),
        duration_seconds=12.5,
        modules_run=["DirBruteforce", "Headers", "Crawler"]
    )
    
    generator = ReportGenerator()
    
    # Convert to dict for the generator (which expects Dict[str, Any])
    result_dict = result.model_dump()
    
    # Generate Dark Theme Report
    dark_html = generator.generate_html(result_dict, theme="dark")
    with open("test_report_dark.html", "w", encoding="utf-8") as f:
        f.write(dark_html)
    print("✅ Dark theme report generated: test_report_dark.html")
    
    # Generate White Theme Report
    white_html = generator.generate_html(result_dict, theme="white")
    with open("test_report_white.html", "w", encoding="utf-8") as f:
        f.write(white_html)
    print("✅ White theme report generated: test_report_white.html")

if __name__ == "__main__":
    # Ensure engine is in path
    sys.path.insert(0, os.getcwd())
    asyncio.run(test_report())
