"use client";

import { useEffect, useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
    Sparkles,
    ChevronDown,
    ChevronUp,
    Loader2,
    AlertTriangle,
    Search,
    CheckSquare,
    Square,
    Filter,
} from "lucide-react";
import { getVortexCategories, type VortexCategory } from "@/lib/api";

interface VortexPanelProps {
    selectedCategories: string[];
    onChange: (categories: string[]) => void;
}

// Severity order and colors
const SEVERITY_META: Record<string, { color: string; bgColor: string; order: number }> = {
    critical: { color: "var(--neon-red)",    bgColor: "rgba(255,0,60,0.12)",    order: 0 },
    high:     { color: "var(--neon-yellow)", bgColor: "rgba(252,238,10,0.10)",  order: 1 },
    medium:   { color: "var(--neon-blue)",   bgColor: "rgba(0,112,255,0.12)",   order: 2 },
    low:      { color: "var(--neon-cyan)",   bgColor: "rgba(0,243,255,0.08)",   order: 3 },
    info:     { color: "var(--text-secondary)", bgColor: "rgba(255,255,255,0.05)", order: 4 },
};

const ALL_SEVERITIES = ["critical", "high", "medium", "low"];

export default function VortexPanel({ selectedCategories, onChange }: VortexPanelProps) {
    const [categories, setCategories] = useState<VortexCategory[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [search, setSearch] = useState("");
    const [severityFilter, setSeverityFilter] = useState<string | null>(null);
    const [expanded, setExpanded] = useState(true);

    // Fetch real categories from the backend
    useEffect(() => {
        let cancelled = false;
        setLoading(true);
        getVortexCategories()
            .then((data) => {
                if (!cancelled) {
                    // Sort: critical → high → medium → low → other
                    const sorted = [...data].sort((a, b) => {
                        const ao = SEVERITY_META[a.severity]?.order ?? 99;
                        const bo = SEVERITY_META[b.severity]?.order ?? 99;
                        if (ao !== bo) return ao - bo;
                        return b.payload_count - a.payload_count;
                    });
                    setCategories(sorted);
                    setError("");
                }
            })
            .catch(() => {
                if (!cancelled) setError("Engine offline — start the backend to load payloads");
            })
            .finally(() => {
                if (!cancelled) setLoading(false);
            });
        return () => { cancelled = true; };
    }, []);

    // Filtered view
    const filtered = useMemo(() => {
        return categories.filter((c) => {
            const matchSearch = !search || c.name.toLowerCase().includes(search.toLowerCase());
            const matchSev = !severityFilter || c.severity === severityFilter;
            return matchSearch && matchSev;
        });
    }, [categories, search, severityFilter]);

    // Stats
    const totalPayloads = categories.reduce((s, c) => s + c.payload_count, 0);
    const selectedPayloads = categories
        .filter((c) => selectedCategories.includes(c.name))
        .reduce((s, c) => s + c.payload_count, 0);

    const toggleCategory = (name: string) => {
        onChange(
            selectedCategories.includes(name)
                ? selectedCategories.filter((c) => c !== name)
                : [...selectedCategories, name]
        );
    };

    const selectAll = (e: React.MouseEvent) => {
        e.preventDefault();
        e.stopPropagation();
        onChange(filtered.map((c) => c.name));
    };

    const clearAll = (e: React.MouseEvent) => {
        e.preventDefault();
        e.stopPropagation();
        onChange([]);
    };

    const selectBySeverity = (sev: string) => {
        const names = categories.filter((c) => c.severity === sev).map((c) => c.name);
        const allSelected = names.every((n) => selectedCategories.includes(n));
        if (allSelected) {
            onChange(selectedCategories.filter((c) => !names.includes(c)));
        } else {
            const merged = Array.from(new Set([...selectedCategories, ...names]));
            onChange(merged);
        }
    };

    return (
        <div className="cyber-card border-[var(--neon-cyan)]/20 relative overflow-hidden mt-4">
            {/* Background glow */}
            <div className="absolute top-0 right-0 w-64 h-64 bg-[var(--neon-cyan)]/5 rounded-full blur-3xl pointer-events-none" />

            {/* Header */}
            <div
                className="flex items-center justify-between p-5 cursor-pointer select-none"
                onClick={() => setExpanded((v) => !v)}
            >
                <div>
                    <h3 className="cyber-label text-[var(--neon-cyan)] text-glow-sm flex items-center gap-2 text-base">
                        <Sparkles className="w-4 h-4" />
                        Vortex_Intel_Engine
                    </h3>
                    <p className="text-[11px] text-[var(--text-secondary)] font-mono mt-1">
                        {loading
                            ? "Loading payload library..."
                            : error
                            ? "Engine offline"
                            : `${categories.length} vuln categories · ${totalPayloads.toLocaleString()} payloads`}
                    </p>
                </div>
                <div className="flex items-center gap-3">
                    {!loading && !error && selectedCategories.length > 0 && (
                        <span className="font-mono text-[10px] uppercase tracking-widest px-2 py-1 rounded"
                            style={{ color: "var(--neon-cyan)", background: "rgba(0,243,255,0.08)", border: "1px solid rgba(0,243,255,0.2)" }}>
                            {selectedCategories.length} sel · {selectedPayloads.toLocaleString()} payloads
                        </span>
                    )}
                    {expanded ? (
                        <ChevronUp className="w-4 h-4 text-[var(--text-secondary)]" />
                    ) : (
                        <ChevronDown className="w-4 h-4 text-[var(--text-secondary)]" />
                    )}
                </div>
            </div>

            <AnimatePresence>
                {expanded && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: "auto", opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        className="overflow-hidden"
                    >
                        <div className="px-5 pb-5 space-y-4 relative z-10">
                            {/* Loading state */}
                            {loading && (
                                <div className="flex items-center gap-3 py-8 justify-center text-[var(--text-secondary)]">
                                    <Loader2 className="w-5 h-5 animate-spin" />
                                    <span className="font-mono text-sm">Scanning payload library...</span>
                                </div>
                            )}

                            {/* Error state */}
                            {!loading && error && (
                                <div className="flex items-center gap-3 py-6 px-4 rounded-lg border border-[var(--neon-red)]/20 bg-[rgba(255,0,60,0.06)]">
                                    <AlertTriangle className="w-5 h-5 text-[var(--neon-red)] flex-shrink-0" />
                                    <div>
                                        <p className="font-mono text-sm text-[var(--neon-red)]">{error}</p>
                                        <p className="font-mono text-[11px] text-[var(--text-secondary)] mt-1">
                                            Run: <code className="text-[var(--neon-cyan)]">uvicorn engine.main:app --reload</code>
                                        </p>
                                    </div>
                                </div>
                            )}

                            {/* Controls */}
                            {!loading && !error && (
                                <>
                                    {/* Search + Quick-select row */}
                                    <div className="flex gap-2 flex-wrap items-center">
                                        {/* Search */}
                                        <div className="flex-1 min-w-[160px] relative">
                                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-secondary)]" />
                                            <input
                                                type="text"
                                                placeholder="Search categories..."
                                                value={search}
                                                onChange={(e) => setSearch(e.target.value)}
                                                onClick={(e) => e.stopPropagation()}
                                                className="w-full bg-black/30 border border-[var(--border-cyber)] rounded pl-8 pr-3 py-1.5 font-mono text-xs text-[var(--text-primary)] placeholder:text-[var(--text-secondary)] focus:outline-none focus:border-[var(--neon-cyan)]/50"
                                            />
                                        </div>

                                        {/* Severity filter */}
                                        <div className="flex gap-1 items-center">
                                            <Filter className="w-3 h-3 text-[var(--text-secondary)]" />
                                            {ALL_SEVERITIES.map((sev) => (
                                                <button
                                                    key={sev}
                                                    type="button"
                                                    onClick={(e) => { e.stopPropagation(); setSeverityFilter(severityFilter === sev ? null : sev); }}
                                                    className="font-mono text-[9px] uppercase tracking-widest px-2 py-1 rounded border transition-all"
                                                    style={{
                                                        color: severityFilter === sev ? SEVERITY_META[sev]?.color : "var(--text-secondary)",
                                                        borderColor: severityFilter === sev ? SEVERITY_META[sev]?.color : "var(--border-cyber)",
                                                        background: severityFilter === sev ? SEVERITY_META[sev]?.bgColor : "transparent",
                                                    }}
                                                >
                                                    {sev}
                                                </button>
                                            ))}
                                        </div>

                                        {/* Select all / clear */}
                                        <button
                                            type="button"
                                            onClick={selectAll}
                                            className="font-mono text-[9px] uppercase tracking-widest px-2.5 py-1.5 rounded border border-[var(--border-cyber)] text-[var(--neon-cyan)] bg-[rgba(0,243,255,0.05)] hover:bg-[rgba(0,243,255,0.15)] transition-colors"
                                        >
                                            All
                                        </button>
                                        <button
                                            type="button"
                                            onClick={clearAll}
                                            className="font-mono text-[9px] uppercase tracking-widest px-2.5 py-1.5 rounded border border-[var(--border-cyber)] text-[var(--text-secondary)] hover:text-[var(--neon-red)] hover:border-[var(--neon-red)]/40 transition-colors"
                                        >
                                            Clear
                                        </button>
                                    </div>

                                    {/* One-click severity rows */}
                                    <div className="flex gap-2 flex-wrap">
                                        {ALL_SEVERITIES.map((sev) => {
                                            const count = categories.filter((c) => c.severity === sev).length;
                                            if (!count) return null;
                                            const meta = SEVERITY_META[sev];
                                            return (
                                                <button
                                                    key={sev}
                                                    type="button"
                                                    onClick={(e) => { e.stopPropagation(); selectBySeverity(sev); }}
                                                    className="font-mono text-[10px] uppercase tracking-widest px-3 py-1 rounded border transition-all hover:opacity-90"
                                                    style={{
                                                        color: meta?.color,
                                                        borderColor: `${meta?.color}40`,
                                                        background: meta?.bgColor,
                                                    }}
                                                >
                                                    + All {sev} ({count})
                                                </button>
                                            );
                                        })}
                                    </div>

                                    {/* Category Grid — virtualized-lite (max 200 visible) */}
                                    <div
                                        className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-[420px] overflow-y-auto pr-1"
                                        style={{ scrollbarWidth: "thin", scrollbarColor: "var(--neon-cyan) transparent" }}
                                    >
                                        {filtered.slice(0, 200).map((cat, i) => {
                                            const isSelected = selectedCategories.includes(cat.name);
                                            const meta = SEVERITY_META[cat.severity] ?? SEVERITY_META.info;

                                            return (
                                                <motion.div
                                                    key={cat.name}
                                                    initial={{ opacity: 0, y: 6 }}
                                                    animate={{ opacity: 1, y: 0 }}
                                                    transition={{ delay: Math.min(i * 0.015, 0.3) }}
                                                    onClick={() => toggleCategory(cat.name)}
                                                    className="flex items-start gap-2.5 p-2.5 rounded-lg border cursor-pointer transition-all group"
                                                    style={{
                                                        borderColor: isSelected ? meta.color : "var(--border-cyber)",
                                                        background: isSelected ? meta.bgColor : "rgba(0,0,0,0.2)",
                                                        boxShadow: isSelected ? `0 0 10px ${meta.color}18` : "none",
                                                    }}
                                                >
                                                    {/* Checkbox icon */}
                                                    <div className="mt-0.5 flex-shrink-0" style={{ color: isSelected ? meta.color : "var(--text-secondary)" }}>
                                                        {isSelected
                                                            ? <CheckSquare className="w-4 h-4" />
                                                            : <Square className="w-4 h-4 group-hover:opacity-70" />}
                                                    </div>

                                                    {/* Info */}
                                                    <div className="min-w-0 flex-1">
                                                        <div className="flex items-center gap-1.5 flex-wrap">
                                                            <span
                                                                className="font-mono text-[11px] font-semibold leading-tight truncate"
                                                                style={{ color: isSelected ? meta.color : "var(--text-primary)" }}
                                                            >
                                                                {cat.name}
                                                            </span>
                                                        </div>
                                                        <div className="flex items-center gap-2 mt-1 flex-wrap">
                                                            <span
                                                                className="font-mono text-[9px] uppercase tracking-widest px-1.5 py-0.5 rounded"
                                                                style={{
                                                                    color: meta.color,
                                                                    background: meta.bgColor,
                                                                    border: `1px solid ${meta.color}30`,
                                                                }}
                                                            >
                                                                {cat.severity}
                                                            </span>
                                                            {cat.payload_count > 0 && (
                                                                <span className="font-mono text-[9px] text-[var(--text-secondary)]">
                                                                    {cat.payload_count.toLocaleString()} payloads
                                                                </span>
                                                            )}
                                                            {cat.cwe && (
                                                                <span className="font-mono text-[9px] text-[var(--text-secondary)] opacity-60">
                                                                    {cat.cwe}
                                                                </span>
                                                            )}
                                                        </div>
                                                    </div>
                                                </motion.div>
                                            );
                                        })}

                                        {filtered.length === 0 && (
                                            <div className="col-span-2 py-8 text-center font-mono text-sm text-[var(--text-secondary)]">
                                                No categories match your filter.
                                            </div>
                                        )}
                                    </div>

                                    {/* Footer summary */}
                                    {selectedCategories.length > 0 && (
                                        <div className="pt-2 border-t border-[var(--border-cyber)] font-mono text-[11px] text-[var(--text-secondary)] flex items-center justify-between">
                                            <span>
                                                {selectedCategories.length} categories selected
                                            </span>
                                            <span style={{ color: "var(--neon-cyan)" }}>
                                                ~{selectedPayloads.toLocaleString()} total payloads queued
                                            </span>
                                        </div>
                                    )}
                                </>
                            )}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
