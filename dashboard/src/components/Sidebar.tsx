"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
    LayoutDashboard,
    Crosshair,
    ListChecks,
    Settings,
    Shield,
    Activity,
} from "lucide-react";

const NAV_ITEMS = [
    { href: "/", label: "Dashboard", icon: LayoutDashboard },
    { href: "/scan", label: "New Scan", icon: Crosshair },
    { href: "/scans", label: "Scan History", icon: ListChecks },
    { href: "/settings", label: "Settings", icon: Settings },
];

export default function Sidebar() {
    const pathname = usePathname();

    return (
        <aside className="fixed left-0 top-0 bottom-0 w-[260px] glass-card border-r border-l-0 border-t-0 border-b-0 rounded-none flex flex-col z-50">
            {/* Brand */}
            <div className="p-6 pb-4 flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-[var(--accent-cyan)] to-[var(--accent-blue)] flex items-center justify-center">
                    <Shield className="w-5 h-5 text-black" />
                </div>
                <div>
                    <h1 className="text-lg font-bold tracking-tight">VAPTx</h1>
                    <p className="text-[0.65rem] text-[var(--text-secondary)] tracking-widest uppercase">
                        Security Platform
                    </p>
                </div>
            </div>

            {/* Status indicator */}
            <div className="px-6 mb-4">
                <div className="glass-card-sm p-3 flex items-center gap-2">
                    <Activity className="w-3.5 h-3.5 text-[var(--accent-cyan)]" />
                    <span className="text-xs text-[var(--text-secondary)]">Engine</span>
                    <span className="ml-auto w-2 h-2 rounded-full bg-[var(--accent-cyan)] pulse-glow" />
                </div>
            </div>

            {/* Nav links */}
            <nav className="flex-1 px-4 space-y-1">
                {NAV_ITEMS.map((item) => {
                    const isActive = pathname === item.href;
                    const Icon = item.icon;
                    return (
                        <Link key={item.href} href={item.href}>
                            <div className={`sidebar-item ${isActive ? "active" : ""}`}>
                                <Icon className="w-4 h-4" />
                                {item.label}
                            </div>
                        </Link>
                    );
                })}
            </nav>

            {/* Footer version */}
            <div className="p-4 text-center text-[0.65rem] text-[var(--text-secondary)] opacity-60">
                v0.1.0 — AI-Powered VAPT
            </div>
        </aside>
    );
}
