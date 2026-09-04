"use client";

import { useState } from "react";
import { Database, Search, ShieldCheck, ShieldAlert, AlertTriangle, Hash, Globe, Server, Check } from "lucide-react";
import { lookupThreat } from "@/lib/api";

export default function ThreatIntelligencePage() {
  const [iocType, setIocType] = useState<"ip" | "domain" | "hash">("domain");
  const [query, setQuery] = useState("microsoft-security.example");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;

    setLoading(true);
    setResult(null);
    try {
      const res = await lookupThreat(iocType, query.trim());
      setResult(res);
    } catch (err: any) {
      setResult({ status: "error", message: err.message || "Lookup query failed" });
    } finally {
      setLoading(false);
    }
  };

  const handleQuickFill = (type: "ip" | "domain" | "hash", val: string) => {
    setIocType(type);
    setQuery(val);
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Title */}
      <div>
        <div className="flex items-center gap-2 mb-1 text-xs font-semibold text-indigo-400 uppercase tracking-wider">
          <Database className="w-3.5 h-3.5" />
          <span>Threat Intelligence Abstraction</span>
        </div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">
          Indicator of Compromise (IOC) Query Engine
        </h1>
        <p className="text-slate-400 text-xs mt-1">
          Unified threat lookup for suspicious IPs, domains, and cryptographic file hashes with transparent provenance attribution.
        </p>
      </div>

      {/* Core Product Principle Banner */}
      <div className="p-4 rounded-xl bg-slate-900 border border-indigo-500/30 text-xs space-y-1">
        <div className="font-bold text-indigo-300 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-indigo-400" />
          Platform Transparency Principle
        </div>
        <p className="text-slate-400 text-[11px] leading-relaxed">
          This platform strictly differentiates between <b>Real Intelligence</b> (via configured API keys), <b>Demo Data</b> (for offline evaluation), and <b>Unconfigured Providers</b>. It will never fabricate external threat scores.
        </p>
      </div>

      {/* Search Input Box */}
      <div className="bg-surface border border-surface-border rounded-xl p-6 space-y-4">
        {/* Type Selector Tabs */}
        <div className="flex border-b border-surface-border gap-4 text-xs font-bold">
          <button
            onClick={() => setIocType("domain")}
            className={`pb-2.5 flex items-center gap-1.5 transition-colors ${
              iocType === "domain"
                ? "border-b-2 border-indigo-500 text-indigo-400"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Globe className="w-4 h-4" />
            <span>Domain Name</span>
          </button>

          <button
            onClick={() => setIocType("ip")}
            className={`pb-2.5 flex items-center gap-1.5 transition-colors ${
              iocType === "ip"
                ? "border-b-2 border-indigo-500 text-indigo-400"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Server className="w-4 h-4" />
            <span>IP Address</span>
          </button>

          <button
            onClick={() => setIocType("hash")}
            className={`pb-2.5 flex items-center gap-1.5 transition-colors ${
              iocType === "hash"
                ? "border-b-2 border-indigo-500 text-indigo-400"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <Hash className="w-4 h-4" />
            <span>File Hash (SHA-256)</span>
          </button>
        </div>

        {/* Input Form */}
        <form onSubmit={handleSearch} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder={
                iocType === "domain"
                  ? "e.g. microsoft-security.example"
                  : iocType === "ip"
                  ? "e.g. 203.0.113.195"
                  : "e.g. e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
              }
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full bg-slate-950 border border-surface-border rounded-lg pl-9 pr-4 py-2 text-xs font-mono text-slate-200 placeholder-slate-400 focus:outline-none focus:border-indigo-500"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-glow transition-all"
          >
            {loading ? "Querying..." : "Scan IOC"}
          </button>
        </form>

        {/* Preset Sample Lookups */}
        <div className="flex flex-wrap items-center gap-2 pt-2 text-[11px] text-slate-400">
          <span>Try sample IOC:</span>
          <button
            type="button"
            onClick={() => handleQuickFill("domain", "microsoft-security.example")}
            className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 font-mono border border-surface-border"
          >
            microsoft-security.example
          </button>
          <button
            type="button"
            onClick={() => handleQuickFill("ip", "203.0.113.195")}
            className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 font-mono border border-surface-border"
          >
            203.0.113.195
          </button>
          <button
            type="button"
            onClick={() => handleQuickFill("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")}
            className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-300 font-mono border border-surface-border"
          >
            SHA-256 Empty
          </button>
        </div>
      </div>

      {/* Results Display */}
      {result && (
        <div className="bg-surface border border-surface-border rounded-xl p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-surface-border pb-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-slate-400 uppercase">Target IOC:</span>
              <span className="font-mono font-bold text-slate-100 text-sm">
                {result.domain || result.ip || result.hash || query}
              </span>
            </div>

            {/* Provider Status Tag */}
            <div>
              {result.data?.provider_status === "demo_intelligence" && (
                <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40">
                  Demo Intelligence Feed
                </span>
              )}
              {result.data?.provider_status === "not_configured" && (
                <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-slate-700/50 text-slate-400 border border-slate-600/40">
                  Provider Not Configured
                </span>
              )}
              {result.data?.provider_status === "active" && (
                <span className="px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                  Live Provider Verified
                </span>
              )}
            </div>
          </div>

          {/* Details Table */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div className="p-3 rounded-lg bg-slate-900/60 border border-surface-border space-y-1">
              <div className="text-slate-400 text-[10px] uppercase font-semibold">Reputation Status</div>
              <div className="text-base font-bold text-slate-100">
                {result.data?.reputation || "Evaluated"}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/60 border border-surface-border space-y-1">
              <div className="text-slate-400 text-[10px] uppercase font-semibold">Provider Threat Score</div>
              <div className="text-base font-bold text-slate-100 font-mono">
                {result.data?.threat_score !== null ? `${result.data?.threat_score} / 100` : "Not Configured"}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/60 border border-surface-border space-y-1">
              <div className="text-slate-400 text-[10px] uppercase font-semibold">Intelligence Feed Source</div>
              <div className="text-slate-200 font-medium">{result.data?.provider_name}</div>
            </div>

            <div className="p-3 rounded-lg bg-slate-900/60 border border-surface-border space-y-1">
              <div className="text-slate-400 text-[10px] uppercase font-semibold">Classification Category</div>
              <div className="text-slate-200 font-medium">
                {result.data?.category || "Standard IOC"}
              </div>
            </div>
          </div>

          {result.data?.note && (
            <div className="p-3 rounded-lg bg-slate-950 text-slate-400 text-xs italic border border-surface-border">
              {result.data?.note}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
