import { motion } from "framer-motion";
import { Link, FileText, Database, ShieldAlert } from "lucide-react";
import type { AttackSurface } from "@/lib/api";

export default function AttackSurfaceView({ data }: { data: AttackSurface }) {
    if (!data) return null;

    return (
        <div className="space-y-6">

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="glass-card p-5 border-t-2 border-t-blue-500">
                    <div className="flex items-center gap-3 mb-2">
                        <Link className="w-5 h-5 text-blue-500" />
                        <h3 className="font-semibold">Discovered URLs</h3>
                    </div>
                    <p className="text-3xl font-bold">{data.internal_urls?.length || 0}</p>
                </div>

                <div className="glass-card p-5 border-t-2 border-t-orange-500">
                    <div className="flex items-center gap-3 mb-2">
                        <FileText className="w-5 h-5 text-orange-500" />
                        <h3 className="font-semibold">HTML Forms</h3>
                    </div>
                    <p className="text-3xl font-bold">{data.forms?.length || 0}</p>
                </div>

                <div className="glass-card p-5 border-t-2 border-t-purple-500">
                    <div className="flex items-center gap-3 mb-2">
                        <Database className="w-5 h-5 text-purple-500" />
                        <h3 className="font-semibold">Input Parameters</h3>
                    </div>
                    <p className="text-3xl font-bold">{data.parameters?.length || 0}</p>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

                {/* Parameters List */}
                <div className="glass-card p-5">
                    <h3 className="text-sm font-semibold uppercase tracking-widest text-[var(--text-secondary)] mb-4 flex items-center gap-2">
                        <Database className="w-4 h-4" />
                        Injection Targets (Parameters)
                    </h3>
                    {data.parameters?.length > 0 ? (
                        <div className="flex flex-wrap gap-2">
                            {data.parameters.map((param, i) => (
                                <span key={i} className="px-3 py-1 bg-black/30 rounded border border-[var(--border-glass)] text-sm font-mono text-purple-400">
                                    ?{param}=
                                </span>
                            ))}
                        </div>
                    ) : (
                        <p className="text-sm text-[var(--text-secondary)]">No parameters discovered.</p>
                    )}
                </div>

                {/* Forms List */}
                <div className="glass-card p-5">
                    <h3 className="text-sm font-semibold uppercase tracking-widest text-[var(--text-secondary)] mb-4 flex items-center gap-2">
                        <FileText className="w-4 h-4" />
                        Discovered Forms
                    </h3>
                    {data.forms?.length > 0 ? (
                        <div className="space-y-3 max-h-[300px] overflow-y-auto pr-2 custom-scrollbar">
                            {data.forms.map((form, i) => (
                                <div key={i} className="bg-black/20 p-3 rounded border border-[var(--border-glass)]">
                                    <div className="flex justify-between items-start mb-2">
                                        <p className="text-sm font-mono truncate text-orange-400" title={form.action}>
                                            {form.action || "(same page)"}
                                        </p>
                                        <span className={`text-xs px-2 py-0.5 rounded font-bold ${form.method === 'POST' ? 'bg-orange-500/20 text-orange-400' : 'bg-blue-500/20 text-blue-400'}`}>
                                            {form.method}
                                        </span>
                                    </div>
                                    <div className="flex gap-2 flex-wrap mt-2">
                                        {form.inputs?.map((inp, idx) => (
                                            <span key={idx} className="text-xs bg-black/40 px-2 py-1 rounded text-[var(--text-secondary)]">
                                                {inp.name || "unnamed"} <span className="opacity-50">({inp.type})</span>
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>
                    ) : (
                        <p className="text-sm text-[var(--text-secondary)]">No forms discovered.</p>
                    )}
                </div>
            </div>

            {/* Internal URLs List */}
            <div className="glass-card p-5">
                <h3 className="text-sm font-semibold uppercase tracking-widest text-[var(--text-secondary)] mb-4 flex items-center gap-2">
                    <Link className="w-4 h-4" />
                    Internal Application Structure
                </h3>
                {data.internal_urls?.length > 0 ? (
                    <div className="max-h-[400px] overflow-y-auto pr-2 custom-scrollbar space-y-1">
                        {data.internal_urls.map((url, i) => (
                            <div key={i} className="text-sm font-mono truncate text-[var(--text-primary)] hover:text-blue-400 p-2 hover:bg-white/5 rounded transition-colors cursor-pointer" title={url}>
                                {url}
                            </div>
                        ))}
                    </div>
                ) : (
                    <p className="text-sm text-[var(--text-secondary)]">No internal URLs discovered.</p>
                )}
            </div>

            {data.external_urls?.length > 0 && (
                <div className="glass-card p-5 border-dashed">
                    <h3 className="text-sm font-semibold uppercase tracking-widest text-[var(--text-secondary)] mb-4 flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-orange-500" />
                        External Dependencies / Outbound Links
                    </h3>
                    <div className="max-h-[200px] overflow-y-auto pr-2 custom-scrollbar space-y-1">
                        {data.external_urls.map((url, i) => (
                            <div key={i} className="text-sm font-mono truncate text-[var(--text-secondary)]" title={url}>
                                {url}
                            </div>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
}
