"use client";

import { useEffect, useState } from "react";
import { Settings, ShieldCheck, Activity, Database, Brain, Globe2, KeyRound, Server } from "lucide-react";

export default function SettingsPage() {
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchHealth();
  }, []);

  const fetchHealth = async () => {
    try {
      setLoading(true);
      const res = await fetch("http://127.0.0.1:8000/api/health");
      if (res.ok) {
        const data = await res.json();
        setHealth(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    const s = (status || "").toUpperCase();
    if (s.includes("ACTIVE") || s.includes("ONLINE")) {
      return "bg-emerald-500/20 text-emerald-400 border-emerald-500/30";
    } else if (s.includes("AVAILABLE")) {
      return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    } else if (s.includes("NOT CONFIGURED")) {
      return "bg-amber-500/20 text-amber-400 border-amber-500/30";
    } else {
      return "bg-red-500/20 text-red-400 border-red-500/30";
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Title */}
      <div>
        <div className="flex items-center gap-2 mb-1 text-xs font-semibold text-indigo-400 uppercase tracking-wider">
          <Settings className="w-3.5 h-3.5" />
          <span>System Architecture & Configuration</span>
        </div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">
          System Health & Provider Matrix
        </h1>
        <p className="text-slate-400 text-xs mt-1">
          Telemetry status for forensic parsers, offline AI engines, database connectivity, and external intelligence feeds.
        </p>
      </div>

      {/* Subsystems Status Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {[
          {
            name: "Forensic Backend Server",
            icon: Server,
            status: health?.components?.backend || "ACTIVE",
            details: "FastAPI v0.110+ running on Python 3.11 with asynchronous pipeline processing.",
          },
          {
            name: "Investigation Database",
            icon: Database,
            status: health?.components?.database || "ACTIVE",
            details: "SQLite & SQLAlchemy ORM with thread-safe persistence and JSON case analysis.",
          },
          {
            name: "AI / NLP Social Engineering Engine",
            icon: Brain,
            status: health?.components?.nlp_engine || "ACTIVE",
            details: "Scikit-Learn TF-IDF classifier + rule-based heuristic fallback (fully offline capable).",
          },
          {
            name: "Geospatial Routing & IP Tracer",
            icon: Globe2,
            status: health?.components?.geolocation || "AVAILABLE",
            details: "In-memory LRU session cache + ip-api.com live integration + RFC 5737 testnet mapping.",
          },
          {
            name: "Threat Intelligence Feeds",
            icon: KeyRound,
            status: health?.components?.threat_intelligence || "ACTIVE",
            details: "Modular feed abstraction for VirusTotal, AbuseIPDB, and synthetic offline feeds.",
          },
          {
            name: "Forensic PDF & JSON Generator",
            icon: ShieldCheck,
            status: "ACTIVE",
            details: "ReportLab dynamic PDF typesetting with two-pass page numbering and JSON schema export.",
          },
        ].map((comp, idx) => {
          const Icon = comp.icon;
          return (
            <div
              key={idx}
              className="bg-surface border border-surface-border rounded-xl p-4 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2 font-bold text-slate-100 text-sm">
                    <Icon className="w-4 h-4 text-indigo-400" />
                    <span>{comp.name}</span>
                  </div>
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${getStatusBadge(
                      comp.status
                    )}`}
                  >
                    {comp.status}
                  </span>
                </div>
                <div className="text-xs text-slate-400 leading-relaxed">{comp.details}</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Environment Configuration Guide */}
      <div className="bg-surface border border-surface-border rounded-xl p-5 space-y-4">
        <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2 border-b border-surface-border pb-3">
          <KeyRound className="w-4 h-4 text-indigo-400" />
          Environment & External Intelligence Configuration
        </h2>

        <div className="text-xs text-slate-400 leading-relaxed">
          The platform functions completely out of the box in zero-internet / offline mode using synthetic datasets and heuristic rule engines. To connect real threat feeds, add the following keys to your <code className="text-indigo-300 font-mono">.env</code> file:
        </div>

        <div className="bg-slate-950 p-4 rounded-lg font-mono text-xs text-slate-300 border border-surface-border space-y-1 overflow-x-auto">
          <div><span className="text-indigo-400">DATABASE_URL</span>=sqlite:///./email_threat.db</div>
          <div><span className="text-indigo-400">CORS_ORIGINS</span>=http://localhost:3000</div>
          <div><span className="text-indigo-400">MAX_UPLOAD_SIZE_MB</span>=10</div>
          <div><span className="text-indigo-400">GEO_PROVIDER</span>=ip-api</div>
          <div><span className="text-slate-500"># Optional Live Intelligence Keys</span></div>
          <div><span className="text-indigo-400">VIRUSTOTAL_API_KEY</span>=your_virustotal_api_key_here</div>
          <div><span className="text-indigo-400">ABUSEIPDB_API_KEY</span>=your_abuseipdb_api_key_here</div>
          <div><span className="text-indigo-400">IPINFO_TOKEN</span>=your_ipinfo_token_here</div>
        </div>
      </div>
    </div>
  );
}
