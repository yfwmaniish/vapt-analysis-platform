# PLAN: Vapt Analysis (Veltro VAPT)

A high-performance, AI-augmented Vulnerability Assessment and Penetration Testing (VAPT) platform designed for real-time threat intelligence and automated security auditing.

## Overview
Veltro VAPT provide a unified command center for security professionals. It combines automated scanning tools (ports, subdomains, secrets) with a "WOW" factor dashboard for visual threat modeling.

## Success Criteria
- [ ] **Functional**: Automated scanner delivers valid findings (JSON/PDF report).
- [ ] **Aesthetic**: Premium "Dark Mode" dashboard with interactive SVG threat maps.
- [ ] **Technical**: Clean separation between Scanning Engine (Python) and Dashboard (Next.js).

## Tech Stack
- **Frontend**: Next.js 15 (App Router), Tailwind CSS 4, Framer Motion, Shadcn/UI.
- **Backend**: Python 3.12, FastAPI, Pydantic (High-speed scanning engine).
- **Security Logic**: Integrations with `nmap` (simulated if binary missing), `regex` secrets detection, and CVE lookup.

## File Structure
```plaintext
/
├── engine/              # Python Scanning Engine
│   ├── main.py          # FastAPI Entry
│   ├── scanner.py       # Vulnerability logic
│   └── models.py        # Pydantic schemas
├── dashboard/           # Next.js Frontend
│   ├── app/             # App Router pages
│   ├── components/      # Sleek UI components
│   └── lib/             # API clients
└── docs/                # Reports & Specs
```

## Task Breakdown

### Phase 1: Foundation (Backend)
- **ID**: `backend-core`
- **Agent**: `backend-specialist`
- **Task**: Initialize FastAPI server with basic security scanning endpoints.
- **Skills**: `python-patterns`, `api-patterns`.
- **INPUT→OUTPUT→VERIFY**: `None` → `engine/main.py` → `GET /health` returns OK.

### Phase 2: Scanning Engine
- **ID**: `vapt-logic`
- **Agent**: `security-auditor`
- **Task**: Implement Regex-based secret detection and subdomain enumerator logic.
- **Skills**: `vulnerability-scanner`, `red-team-tactics`.
- **INPUT→OUTPUT→VERIFY**: `Target URL` → `scanner.py` results → Test with known secret pattern.

### Phase 3: Premium UI (Dashboard)
- **ID**: `frontend-ui`
- **Agent**: `frontend-specialist`
- **Task**: Scaffold Next.js dashboard with "Glassmorphism" aesthetic and interactive threat cards.
- **Skills**: `frontend-design`, `ui-ux-pro-max`, `react-best-practices`.
- **INPUT→OUTPUT→VERIFY**: `Project Spec` → `dashboard/` → Visual check for 2025 premium standards.

### Phase 4: Integration & UX
- **ID**: `integration`
- **Agent**: `orchestrator`
- **Task**: Connect Frontend to Backend scanner and add real-time scan progress bars.
- **Skills**: `parallel-agents`.
- **INPUT→OUTPUT→VERIFY**: `Dashboard click` → `Scan trigger` → Results display in UI.

## Phase X: Verification
- [ ] `python .agent/scripts/checklist.py .`
- [ ] `python .agent/skills/vulnerability-scanner/scripts/security_scan.py .`
- [ ] `npm run build` (in dashboard)
- [ ] Manual check: No purple/violet used.
