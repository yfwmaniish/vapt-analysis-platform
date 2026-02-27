"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { Settings, Key, Server, Brain, Save, CheckCircle } from "lucide-react";

export default function SettingsPage() {
    const [saved, setSaved] = useState(false);
    const [settings, setSettings] = useState({
        apiBase: "http://localhost:8000",
        shodanKey: "",
        vtKey: "",
        llmKey: "",
        llmModel: "anthropic/claude-sonnet-4",
    });

    const handleSave = () => {
        // Store in localStorage for now
        if (typeof window !== "undefined") {
            localStorage.setItem("vaptx_settings", JSON.stringify(settings));
        }
        setSaved(true);
        setTimeout(() => setSaved(false), 2000);
    };

    return (
        <div className="max-w-3xl mx-auto space-y-6">
            <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
                <h1 className="text-2xl font-bold flex items-center gap-3">
                    <Settings className="w-6 h-6 text-[var(--accent-cyan)]" />
                    Settings
                </h1>
                <p className="text-sm text-[var(--text-secondary)] mt-1">
                    Configure API keys and engine connection
                </p>
            </motion.div>

            {/* Engine Connection */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.1 }}
                className="glass-card p-6"
            >
                <h2 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-widest mb-4 flex items-center gap-2">
                    <Server className="w-4 h-4" />
                    Engine Connection
                </h2>
                <div>
                    <label className="text-xs text-[var(--text-secondary)] block mb-1">
                        Backend API URL
                    </label>
                    <input
                        type="text"
                        value={settings.apiBase}
                        onChange={(e) => setSettings({ ...settings, apiBase: e.target.value })}
                        className="input-dark"
                    />
                </div>
            </motion.div>

            {/* API Keys */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
                className="glass-card p-6 space-y-4"
            >
                <h2 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-widest mb-2 flex items-center gap-2">
                    <Key className="w-4 h-4" />
                    API Keys
                </h2>

                <div>
                    <label className="text-xs text-[var(--text-secondary)] block mb-1">
                        Shodan API Key
                    </label>
                    <input
                        type="password"
                        value={settings.shodanKey}
                        onChange={(e) => setSettings({ ...settings, shodanKey: e.target.value })}
                        placeholder="Enter Shodan API key"
                        className="input-dark font-mono"
                    />
                </div>

                <div>
                    <label className="text-xs text-[var(--text-secondary)] block mb-1">
                        VirusTotal API Key
                    </label>
                    <input
                        type="password"
                        value={settings.vtKey}
                        onChange={(e) => setSettings({ ...settings, vtKey: e.target.value })}
                        placeholder="Enter VirusTotal API key"
                        className="input-dark font-mono"
                    />
                </div>
            </motion.div>

            {/* AI Configuration */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="glass-card p-6 space-y-4"
            >
                <h2 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-widest mb-2 flex items-center gap-2">
                    <Brain className="w-4 h-4" />
                    AI Configuration
                </h2>

                <div>
                    <label className="text-xs text-[var(--text-secondary)] block mb-1">
                        OpenRouter API Key
                    </label>
                    <input
                        type="password"
                        value={settings.llmKey}
                        onChange={(e) => setSettings({ ...settings, llmKey: e.target.value })}
                        placeholder="sk-or-v1-..."
                        className="input-dark font-mono"
                    />
                </div>

                <div>
                    <label className="text-xs text-[var(--text-secondary)] block mb-1">
                        LLM Model
                    </label>
                    <input
                        type="text"
                        value={settings.llmModel}
                        onChange={(e) => setSettings({ ...settings, llmModel: e.target.value })}
                        className="input-dark font-mono"
                    />
                    <p className="text-[0.65rem] text-[var(--text-secondary)] mt-1">
                        e.g. anthropic/claude-sonnet-4, openai/gpt-4o, google/gemini-2.5-flash
                    </p>
                </div>
            </motion.div>

            {/* Save */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.4 }}
            >
                <button onClick={handleSave} className="btn-primary flex items-center gap-2">
                    {saved ? (
                        <>
                            <CheckCircle className="w-4 h-4" />
                            Saved!
                        </>
                    ) : (
                        <>
                            <Save className="w-4 h-4" />
                            Save Settings
                        </>
                    )}
                </button>
            </motion.div>
        </div>
    );
}
