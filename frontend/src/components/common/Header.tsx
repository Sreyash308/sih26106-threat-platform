"use client";

import Link from "next/link";
import { Search, Bell, ShieldCheck, UserCheck, PlusCircle } from "lucide-react";

export default function Header() {
  return (
    <header className="h-16 border-b border-surface-border bg-surface/80 backdrop-blur-md sticky top-0 z-20 px-6 flex items-center justify-between">
      {/* Search Bar */}
      <div className="flex items-center gap-3 w-96">
        <div className="relative w-full">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search investigation ID, IOC hash, domain, or IP..."
            className="w-full bg-slate-900/90 border border-surface-border rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-indigo-500 transition-colors"
          />
        </div>
      </div>

      {/* Right Tools & Analyst Profile */}
      <div className="flex items-center gap-4">
        {/* Quick Action */}
        <Link
          href="/analyze"
          className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-3 py-1.5 rounded-lg transition-all shadow-sm"
        >
          <PlusCircle className="w-3.5 h-3.5" />
          <span>New Analysis</span>
        </Link>

        {/* System Health Badge */}
        <div className="hidden md:flex items-center gap-2 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-medium">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>SOC Shield Active</span>
        </div>

        {/* Notifications Icon */}
        <button
          title="Notifications"
          className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 relative transition-colors"
        >
          <Bell className="w-4 h-4" />
          <span className="w-2 h-2 rounded-full bg-indigo-500 absolute top-1.5 right-1.5" />
        </button>

        {/* Analyst Profile */}
        <div className="flex items-center gap-3 pl-3 border-l border-surface-border">
          <div className="w-8 h-8 rounded-full bg-slate-800 border border-indigo-500/40 flex items-center justify-center text-indigo-300 font-bold text-xs">
            <UserCheck className="w-4 h-4" />
          </div>
          <div className="text-left hidden sm:block">
            <div className="text-xs font-semibold text-slate-200">Forensics Lead</div>
            <div className="text-[10px] text-slate-400">SOC Analyst #26106</div>
          </div>
        </div>
      </div>
    </header>
  );
}
