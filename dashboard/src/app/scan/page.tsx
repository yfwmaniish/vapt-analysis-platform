"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import {
    Target,
    Crosshair,
    Wifi,
    Lock,
    Globe,
    Cloud,
    Server,
    Key,
    ShieldCheck,
    Cookie,
    FolderSearch,
    Radio,
    Search,
    Zap,
    Monitor,
    Loader2,
    FileCode,
    Fingerprint,
    Scan,
    Link,
    Cpu,
} from "lucide-react";
import {
    createScan,
    getAvailableScanners,
    type ScanRequest,
    type ScannerInfo,
} from "@/lib/api";

/* ── Module Icon Map ────────────────────────────────────────── */
const MODULE_ICONS: Record<string, any> = {
    port_scan: Wifi,
    ssl_scan: Lock,
    subdomain: Globe,
    s3_bucket: Cloud,
    ftp: Server,
    jwt: Key,
    headers: ShieldCheck,
    cookies: Cookie,
    dir_bruteforce: FolderSearch,
    endpoints: Radio,
    dorking: Search,
    crawler: Globe,
    fuzzer: Zap,
    browser: Monitor,
    ssrf: Server,
    xxe: FileCode,
    session: Fingerprint,
    fingerprint: Scan,
    cors: Link,
    redirect: Cpu,
};

export default function ScanPage() {
    const router = useRouter();
    const [target, setTarget] = useState("");
    const [selectedModules, setSelectedModules] = useState<string[]>([]);
    const [allModules, setAllModules] = useState<ScannerInfo[]>([]);
    const [jwtToken, setJwtToken] = useState("");
    const [authHeader, setAuthHeader] = useState("");
    const [aiEnabled, setAiEnabled] = useState(true);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    // Load available scanners
    useEffect(() => {
        getAvailableScanners()
            .then((scanners) => {
                setAllModules(scanners);
                setSelectedModules(scanners.map((s) => s.name));
            })
            .catch(() => { });
    }, []);

    const toggleModule = (name: string) => {
        setSelectedModules((prev) =>
            prev.includes(name) ? prev.filter((m) => m !== name) : [...prev, name]
        );
    };

    const selectAll = () => setSelectedModules(allModules.map((m) => m.name));
    const deselectAll = () => setSelectedModules([]);

    const handleScan = async () => {
        if (!target.trim()) {
            setError("Enter a target domain or URL");
            return;
        }
        if (selectedModules.length === 0) {
            setError("Select at least one scanner module");
            return;
        }

        setLoading(true);
        setError("");
        try {
            const req: ScanRequest = {
                target: target.trim(),
                modules: selectedModules,
                ai_analysis: aiEnabled,
            };
            if (jwtToken.trim()) req.jwt_token = jwtToken.trim();
            if (authHeader.trim()) req.auth_header = authHeader.trim();

            const res = await createScan(req);
            router.push(`/scans/${res.scan_id}`);
        } catch (err: any) {
            setError(err.message || "Failed to start scan");
            setLoading(false);
        }
    };

    return (
        <div className="max-w-4xl mx-auto space-y-6">
            {/* Header */}
            <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
                <h1 className="text-2xl font-bold flex items-center gap-3">
                    <Crosshair className="w-6 h-6 text-[var(--accent-cyan)]" />
                    New Scan
                </h1>
                <p className="text-sm text-[var(--text-secondary)] mt-1">
                    Configure and launch a security assessment against your target
                </p>
            </motion.div>

            {/* Target Input */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
                className="glass-card p-6"
            >
                <label className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-widest block mb-3">
                    <Target className="w-4 h-4 inline mr-2" />
                    Target
                </label>
                <input
                    type="text"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="example.com or https://example.com"
                    className="input-dark text-lg"
                    onKeyDown={(e) => e.key === "Enter" && handleScan()}
                />
            </motion.div>

            {/* Module Selector */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="glass-card p-6"
            >
                <div className="flex items-center justify-between mb-4">
                    <label className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-widest">
                        Scanner Modules
                    </label>
                    <div className="flex gap-2">
                        <button
                            onClick={selectAll}
                            className="text-xs text-[var(--accent-cyan)] hover:underline"
                        >
                            Select All
                        </button>
                        <span className="text-xs text-[var(--text-secondary)]">|</span>
                        <button
                            onClick={deselectAll}
                            className="text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:underline"
                        >
                            Deselect All
                        </button>
                    </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {allModules.map((mod) => {
                        const selected = selectedModules.includes(mod.name);
                        const Icon = MODULE_ICONS[mod.name] || ShieldCheck;
                        return (
                            <motion.button
                                key={mod.name}
                                onClick={() => toggleModule(mod.name)}
                                whileHover={{ scale: 1.02 }}
                                whileTap={{ scale: 0.98 }}
                                className={`glass-card-sm p-4 text-left transition-all duration-200 cursor-pointer ${selected
                                    ? "border-[var(--accent-cyan)] bg-[rgba(6,214,160,0.05)]"
                                    : "opacity-50 hover:opacity-80"
                                    }`}
                                style={{
                                    borderColor: selected ? "var(--accent-cyan)" : undefined,
                                }}
                            >
                                <div className="flex items-center gap-3">
                                    <div
                                        className="w-8 h-8 rounded-lg flex items-center justify-center"
                                        style={{
                                            background: selected
                                                ? "rgba(6,214,160,0.15)"
                                                : "rgba(255,255,255,0.03)",
                                        }}
                                    >
                                        <Icon
                                            className="w-4 h-4"
                                            style={{
                                                color: selected ? "var(--accent-cyan)" : "var(--text-secondary)",
                                            }}
                                        />
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <p className="text-sm font-medium truncate">{mod.display_name}</p>
                                        <p className="text-[0.65rem] text-[var(--text-secondary)] truncate">
                                            {mod.description}
                                        </p>
                                    </div>
                                </div>
                            </motion.button>
                        );
                    })}
                </div>
            </motion.div>

            {/* Advanced Options */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="glass-card p-6 space-y-4"
            >
                <label className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-widest block">
                    Advanced Options
                </label>

                {/* JWT Token */}
                <div>
                    <label className="text-xs text-[var(--text-secondary)] block mb-1">
                        JWT Token (optional — for JWT analysis)
                    </label>
                    <input
                        type="text"
                        value={jwtToken}
                        onChange={(e) => setJwtToken(e.target.value)}
                        placeholder="eyJhbGciOiJIUzI1NiIs..."
                        className="input-dark text-sm font-mono"
                    />
                </div>

                {/* Global Auth Header */}
                <div>
                    <label className="text-xs text-[var(--text-secondary)] block mb-1">
                        Authorization Header (optional — for authenticated scanning)
                    </label>
                    <input
                        type="text"
                        value={authHeader}
                        onChange={(e) => setAuthHeader(e.target.value)}
                        placeholder="Bearer eyJhbGciOiJIUzI1NiIs..."
                        className="input-dark text-sm font-mono"
                    />
                    <p className="text-[0.6rem] text-[var(--text-secondary)] mt-1 opacity-60">
                        This header will be sent with all scanner requests, allowing scanning behind login walls.
                    </p>
                </div>

                {/* AI Toggle */}
                <div className="flex items-center justify-between">
                    <div>
                        <p className="text-sm font-medium">AI Analysis</p>
                        <p className="text-xs text-[var(--text-secondary)]">
                            Generate AI-powered remediation suggestions
                        </p>
                    </div>
                    <button
                        onClick={() => setAiEnabled(!aiEnabled)}
                        className={`w-12 h-6 rounded-full transition-all duration-200 ${aiEnabled ? "bg-[var(--accent-cyan)]" : "bg-gray-600"
                            }`}
                    >
                        <div
                            className={`w-5 h-5 rounded-full bg-white transition-all duration-200 ${aiEnabled ? "translate-x-6" : "translate-x-0.5"
                                }`}
                        />
                    </button>
                </div>
            </motion.div>

            {/* Error */}
            <AnimatePresence>
                {error && (
                    <motion.div
                        initial={{ opacity: 0, y: -10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0 }}
                        className="glass-card p-4 border-[var(--severity-critical)] text-[var(--severity-critical)] text-sm"
                    >
                        {error}
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Launch Button */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 }}
            >
                <button
                    onClick={handleScan}
                    disabled={loading}
                    className="btn-primary w-full py-4 text-base flex items-center justify-center gap-3"
                >
                    {loading ? (
                        <>
                            <Loader2 className="w-5 h-5 animate-spin" />
                            Launching Scan...
                        </>
                    ) : (
                        <>
                            <Zap className="w-5 h-5" />
                            Launch Security Scan
                        </>
                    )}
                </button>
            </motion.div>
        </div>
    );
}
