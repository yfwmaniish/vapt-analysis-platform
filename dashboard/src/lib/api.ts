/**
 * API service layer for the VAPTx dashboard.
 * Handles all communication with the FastAPI backend.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";
const WS_BASE = API_BASE.replace("http", "ws");

/* ── Types ─────────────────────────────────────────────────── */

export interface ScanRequest {
    target: string;
    modules: string[];
    jwt_token?: string;
    auth_header?: string;
    timeout?: number;
    threads?: number;
    ai_analysis?: boolean;
}

export interface ScanResponse {
    scan_id: string;
    status: string;
    target: string;
    modules: string[];
    created_at: string;
}

export interface AttackSurfaceForm {
    action: string;
    method: string;
    inputs: { name: string; type: string }[];
    found_on: string;
}

export interface AttackSurface {
    internal_urls: string[];
    external_urls: string[];
    forms: AttackSurfaceForm[];
    parameters: string[];
}

export interface ScanResult {
    scan_id: string;
    status: string;
    target: string;
    modules_run: string[];
    created_at: string;
    completed_at?: string;
    duration_seconds?: number;
    findings: Finding[];
    ai_summary?: string;
    attack_surface?: AttackSurface;
}

export interface Finding {
    scanner: string;
    type: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    title: string;
    description: string;
    evidence?: string;
    location?: string;
    remediation?: string;
    cwe_id?: string;
    cvss_score?: number;
    references?: string[];
    ai_analysis?: string;
}

export interface ScanListItem {
    scan_id: string;
    target: string;
    status: string;
    created_at: string;
    completed_at?: string;
    duration_seconds?: number;
    findings_count: number;
    critical_count: number;
    high_count: number;
}

export interface ProgressEvent {
    type: "progress" | "complete";
    scan_id: string;
    module?: string;
    percentage?: number;
    message?: string;
    status?: string;
    findings_count?: number;
}

export interface ScannerInfo {
    name: string;
    display_name: string;
    description: string;
}

/* ── API Methods ───────────────────────────────────────────── */

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
    const res = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers: { "Content-Type": "application/json", ...options?.headers },
    });
    if (!res.ok) {
        const text = await res.text();
        throw new Error(`API Error ${res.status}: ${text}`);
    }
    return res.json();
}

export async function createScan(req: ScanRequest): Promise<ScanResponse> {
    return apiFetch<ScanResponse>("/api/scans", {
        method: "POST",
        body: JSON.stringify(req),
    });
}

export async function listScans(): Promise<ScanListItem[]> {
    return apiFetch<ScanListItem[]>("/api/scans");
}

export async function getScan(scanId: string): Promise<ScanResult> {
    return apiFetch<ScanResult>(`/api/scans/${scanId}`);
}

export async function getScanProgress(scanId: string) {
    return apiFetch<{ scan_id: string; status: string; events: any[] }>(
        `/api/scans/${scanId}/progress`
    );
}

export async function getAvailableScanners(): Promise<ScannerInfo[]> {
    return apiFetch<ScannerInfo[]>("/api/scans/scanners/available");
}

export async function healthCheck() {
    return apiFetch<{
        status: string;
        engine: string;
        version: string;
        scanners_loaded: number;
        ai_available: boolean;
    }>("/health");
}

/* ── WebSocket ─────────────────────────────────────────────── */

export function connectScanWS(
    scanId: string,
    onEvent: (event: ProgressEvent) => void,
    onClose?: () => void
): WebSocket {
    const ws = new WebSocket(`${WS_BASE}/api/ws/scan/${scanId}`);
    ws.onmessage = (e) => {
        try {
            const data = JSON.parse(e.data);
            onEvent(data);
        } catch { }
    };
    ws.onclose = () => onClose?.();
    return ws;
}
