"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import {
    Crosshair,
    Shield,
    Globe,
    FileCode,
    Network,
    Key,
    Activity,
    Brain,
    Loader2,
    Settings,
    ChevronDown,
    ChevronUp,
    Zap
} from "lucide-react";
import { createScan } from "@/lib/api";
import VortexPanel from "@/components/VortexPanel";

// Reusing same mapping, just keeping it inside component for simplicity or keeping it clean
const MODULE_ICONS: Record<string, any> = {
    vortex: Activity,
    nmap: Network,
    nuclei: Zap,
    ffuf: Globe,
    zap: Shield,
};

const AVAILABLE_MODULES = [
    { id: "vortex", name: "Vortex Intelligence", desc: "Proprietary deep-scan engine with AI correlation", backend_modules: ["vortex"] },
    { id: "nmap", name: "Nmap Scanner", desc: "Network discovery and security auditing", backend_modules: ["port_scan", "ssl_scan", "ftp"] },
    { id: "nuclei", name: "Nuclei Engine", desc: "Fast and customizable vulnerability scanner", backend_modules: ["ssrf", "xxe", "cors", "redirect", "jwt", "s3_bucket", "subdomain"] },
    { id: "ffuf", name: "FFuF Fuzzer", desc: "Fast web fuzzer for directory and parameter discovery", backend_modules: ["dir_bruteforce", "fuzzer"] },
    { id: "zap", name: "OWASP ZAP", desc: "Integrated baseline web application scanner", backend_modules: ["crawler", "browser", "endpoints", "headers", "cookies", "session", "fingerprint"] },
];

export default function NewScanPage() {
    const router = useRouter();
    const [target, setTarget] = useState("");
    const [modules, setModules] = useState<string[]>(["vortex", "nmap"]);
    const [useAi, setUseAi] = useState(true);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");

    // Advanced Options State
    const [showAdvanced, setShowAdvanced] = useState(false);
    const [jwtToken, setJwtToken] = useState("");
    const [customHeaders, setCustomHeaders] = useState("");

    // Vortex specific state - default to highest impact to avoid 83k tests
    const [vortexCategories, setVortexCategories] = useState<string[]>([
        "SQL Injection", 
        "XSS Injection", 
        "Command Injection"
    ]);

    const toggleModule = (id: string) => {
        setModules((prev) =>
            prev.includes(id) ? prev.filter((m) => m !== id) : [...prev, id]
        );
    };

    const handleStart = async (e: React.FormEvent) => {
        e.preventDefault();
        setError("");

        if (!target) {
            setError("Target URL is required. Example: https://example.com");
            return;
        }

        if (modules.length === 0) {
            setError("Please select at least one scanner module.");
            return;
        }

        try {
            setLoading(true);

            // Parse custom headers safely
            let headersObj: Record<string, string> | undefined;
            if (customHeaders.trim()) {
                try {
                    headersObj = {};
                    const lines = customHeaders.split('\n');
                    for (const line of lines) {
                        const colonIdx = line.indexOf(':');
                        if (colonIdx > 0) {
                            const key = line.slice(0, colonIdx).trim();
                            const val = line.slice(colonIdx + 1).trim();
                            if (key && val) headersObj[key] = val;
                        }
                    }
                } catch (e) {
                    throw new Error("Invalid custom headers format. Use 'Header-Name: Value' format");
                }
            }

            // Expand selected UI modules to backend modules
            const backendModules = new Set<string>();
            modules.forEach(mId => {
                const mod = AVAILABLE_MODULES.find(m => m.id === mId);
                if (mod && mod.backend_modules) {
                    mod.backend_modules.forEach(bm => backendModules.add(bm));
                }
            });

            const response = await createScan({
                target,
                modules: Array.from(backendModules),
                ai_analysis: useAi,
                jwt_token: jwtToken.trim() || undefined,
                auth_header: customHeaders.trim() || undefined,
                vortex_categories: modules.includes('vortex') && vortexCategories.length > 0 ? vortexCategories : undefined
            });

            router.push(`/scans/${response.scan_id}`);
        } catch (err: any) {
            setError(err.message || "Failed to initialize scan sequence.");
            setLoading(false);
        }
    };

    return (
        <div className="max-w-4xl mx-auto space-y-6">
            <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
                <h1 className="text-2xl font-bold font-mono tracking-wide flex items-center gap-3">
                    <Crosshair className="w-6 h-6 text-[var(--neon-cyan)]" />
                    Initialize_Scan
                </h1>
                <p className="cyber-label mt-2">
                    Configure target parameters and module payload
                </p>
            </motion.div>

            <form onSubmit={handleStart} className="space-y-6">
                {/* Target Configuration */}
                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.1 }}
                    className="cyber-card p-6"
                >
                    <h2 className="cyber-label flex items-center gap-2 mb-4">
                        <Globe className="w-4 h-4 text-[var(--neon-cyan)]" />
                        Target_Directive
                    </h2>

                    <div className="relative">
                        <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
                            <span className="font-mono text-[var(--neon-cyan)] font-bold text-lg">&gt;</span>
                        </div>
                        <input
                            type="url"
                            placeholder="https://target-application.com"
                            value={target}
                            onChange={(e) => setTarget(e.target.value)}
                            className="input-dark pl-10 font-mono text-lg"
                            required
                        />
                    </div>
                </motion.div>

                {/* Module Selection */}
                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.2 }}
                    className="space-y-4"
                >
                    <div className="flex items-center justify-between">
                        <h2 className="cyber-label flex items-center gap-2">
                            <Layers className="w-4 h-4 text-[var(--neon-blue)]" />
                            Module_Matrix
                        </h2>
                        <span className="font-mono text-[10px] text-[var(--text-secondary)]">
                            {modules.length} / {AVAILABLE_MODULES.length} ARMED
                        </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {AVAILABLE_MODULES.map((mod) => {
                            const isSelected = modules.includes(mod.id);
                            const Icon = MODULE_ICONS[mod.id] || Shield;

                            return (
                                <div
                                    key={mod.id}
                                    onClick={() => toggleModule(mod.id)}
                                    className={`cyber-card-sm p-4 cursor-pointer flex items-start gap-4 transition-all group ${isSelected
                                        ? "border-[var(--neon-cyan)] bg-[rgba(0,243,255,0.05)] shadow-[0_0_15px_rgba(0,243,255,0.1)]"
                                        : "hover:border-[var(--border-cyber-hover)] hover:bg-[rgba(255,255,255,0.02)]"
                                        }`}
                                >
                                    <div className={`p-2 rounded border transition-colors ${isSelected
                                        ? "bg-[var(--neon-cyan)]/20 border-[var(--neon-cyan)] text-[var(--neon-cyan)]"
                                        : "bg-black/30 border-[var(--border-cyber)] text-[var(--text-secondary)] group-hover:text-[var(--text-primary)]"
                                        }`}>
                                        <Icon className="w-5 h-5" />
                                    </div>
                                    <div className="flex-1 min-w-0 pt-0.5">
                                        <div className="flex items-center justify-between">
                                            <p className={`font-mono text-sm font-bold ${isSelected ? "text-[var(--neon-cyan)] text-glow-sm" : "text-[var(--text-primary)]"}`}>
                                                {mod.name.toUpperCase()}
                                            </p>
                                            {/* Status Dot */}
                                            <div className="flex items-center gap-1.5">
                                                <div className={`w-1.5 h-1.5 rounded-full ${isSelected ? "bg-[var(--neon-cyan)] pulse-glow" : "bg-[var(--text-secondary)]/30"}`} />
                                            </div>
                                        </div>
                                        <p className="text-xs text-[var(--text-secondary)] mt-1 font-mono opacity-80 leading-relaxed">
                                            {mod.desc}
                                        </p>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </motion.div>

                {/* Vortex Panel Integration */}
                <AnimatePresence>
                    {modules.includes('vortex') && (
                        <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="overflow-hidden"
                        >
                            <VortexPanel
                                selectedCategories={vortexCategories}
                                onChange={setVortexCategories}
                            />
                        </motion.div>
                    )}
                </AnimatePresence>


                {/* AI & Advanced Options */}
                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3 }}
                    className="grid grid-cols-1 md:grid-cols-2 gap-4"
                >
                    {/* AI Correlation Toggle */}
                    <div
                        onClick={() => setUseAi(!useAi)}
                        className={`cyber-card-sm p-4 cursor-pointer flex items-center justify-between transition-colors ${useAi ? "border-[var(--neon-purple)] bg-[rgba(188,19,254,0.05)]" : ""
                            }`}
                    >
                        <div className="flex items-center gap-3">
                            <div className={`p-1.5 rounded ${useAi ? "bg-[var(--neon-purple)]/20 text-[var(--neon-purple)]" : "text-[var(--text-secondary)]"}`}>
                                <Brain className="w-5 h-5" />
                            </div>
                            <div>
                                <h3 className={`font-mono text-sm font-bold ${useAi ? "text-[var(--neon-purple)] text-glow-sm" : ""}`}>
                                    AI_CORRELATION
                                </h3>
                                <p className="text-xs text-[var(--text-secondary)] font-mono opacity-80">
                                    Analyze findings with GenAI
                                </p>
                            </div>
                        </div>
                        <div className={`w-10 h-5 rounded-full relative transition-colors ${useAi ? "bg-[var(--neon-purple)]/30 border border-[var(--neon-purple)]" : "bg-black/50 border border-[var(--border-cyber)]"}`}>
                            <div className={`absolute top-0.5 w-3.5 h-3.5 rounded-full bg-white transition-all shadow-[0_0_5px_rgba(255,255,255,0.8)] ${useAi ? "left-[20px]" : "left-1 opacity-50"}`} />
                        </div>
                    </div>

                    {/* Advanced Opts Toggle */}
                    <div
                        onClick={() => setShowAdvanced(!showAdvanced)}
                        className={`cyber-card-sm p-4 cursor-pointer flex items-center justify-between transition-colors ${showAdvanced ? "border-[var(--text-primary)]" : "hover:border-[var(--border-cyber-hover)]"
                            }`}
                    >
                        <div className="flex items-center gap-3">
                            <div className="p-1.5 rounded text-[var(--text-secondary)]">
                                <Settings className="w-5 h-5" />
                            </div>
                            <div>
                                <h3 className="font-mono text-sm font-bold">AUTH_INJECTORS</h3>
                                <p className="text-xs text-[var(--text-secondary)] font-mono opacity-80">
                                    Headers, Tokens, Config
                                </p>
                            </div>
                        </div>
                        {showAdvanced ? (
                            <ChevronUp className="w-4 h-4 text-[var(--text-secondary)]" />
                        ) : (
                            <ChevronDown className="w-4 h-4 text-[var(--text-secondary)]" />
                        )}
                    </div>
                </motion.div>

                {/* Advanced Options Content */}
                <AnimatePresence>
                    {showAdvanced && (
                        <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: "auto" }}
                            exit={{ opacity: 0, height: 0 }}
                            className="cyber-card p-6 overflow-hidden"
                        >
                            <div className="space-y-5">
                                <div>
                                    <label className="cyber-label flex items-center gap-2 mb-2">
                                        <Key className="w-4 h-4 text-[var(--neon-yellow)]" />
                                        Bearer_Token
                                    </label>
                                    <input
                                        type="text"
                                        placeholder="eyJhbGciOiJIUzI1NiIsInR..."
                                        value={jwtToken}
                                        onChange={(e) => setJwtToken(e.target.value)}
                                        className="input-dark font-mono text-xs"
                                    />
                                </div>
                                <div>
                                    <label className="cyber-label flex items-center gap-2 mb-2">
                                        <FileCode className="w-4 h-4 text-[var(--neon-yellow)]" />
                                        Custom_Headers
                                    </label>
                                    <textarea
                                        placeholder="X-Custom-Auth: value123&#10;Cookie: session=xyz"
                                        value={customHeaders}
                                        onChange={(e) => setCustomHeaders(e.target.value)}
                                        className="input-dark font-mono text-xs min-h-[100px] resize-y"
                                    />
                                    <p className="text-[10px] text-[var(--text-secondary)] font-mono mt-1.5">
                                        Format: Key: Value (one per line)
                                    </p>
                                </div>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>

                {error && (
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        className="p-4 rounded-md border border-[var(--severity-critical)] bg-[rgba(255,0,60,0.1)] text-[var(--severity-critical)] font-mono flex items-start gap-3"
                    >
                        <Shield className="w-5 h-5 flex-shrink-0 mt-0.5" />
                        <span className="text-sm">{error}</span>
                    </motion.div>
                )}

                <motion.button
                    whileHover={{ scale: 1.01 }}
                    whileTap={{ scale: 0.98 }}
                    type="submit"
                    disabled={loading || modules.length === 0 || !target}
                    className="w-full btn-primary py-4 text-base flex justify-center items-center gap-3 relative overflow-hidden group border border-[var(--neon-cyan)] shadow-[0_0_20px_rgba(0,243,255,0.2)]"
                >
                    {/* Button scanline effect overlay */}
                    <div className="absolute inset-0 bg-[linear-gradient(rgba(255,255,255,0.1)_1px,transparent_1px)] bg-[length:100%_4px] opacity-20 pointer-events-none" />

                    {loading ? (
                        <>
                            <Loader2 className="w-5 h-5 animate-spin" />
                            INITIALIZING_SEQUENCE...
                        </>
                    ) : (
                        <>
                            <Activity className="w-5 h-5 group-hover:scale-110 transition-transform" />
                            <span className="text-glow-sm">LAUNCH_VORTEX_PROTOCOL</span>
                        </>
                    )}
                </motion.button>
            </form>
        </div>
    );
}

// Needed to fix the lucide missing icon reference
const Layers = Shield;
