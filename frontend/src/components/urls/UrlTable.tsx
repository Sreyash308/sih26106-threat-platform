"use client";

import { URLItem, CryptoIndicator } from "@/lib/types";
import { Link2, AlertTriangle, ExternalLink, Coins, AlertCircle } from "lucide-react";
import { getSeverityStyle } from "@/lib/utils";

interface UrlTableProps {
  urls: URLItem[];
  cryptoIndicators?: CryptoIndicator[];
}

export default function UrlTable({ urls = [], cryptoIndicators = [] }: UrlTableProps) {
  return (
    <div className="space-y-6">
      {/* Extracted URLs Card */}
      <div className="bg-surface border border-surface-border rounded-xl p-5">
        <div className="flex items-center justify-between border-b border-surface-border pb-3 mb-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400">
              <Link2 className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100">
                Extracted Hyperlinks ({urls.length})
              </h3>
              <p className="text-[11px] text-slate-400">
                Passive inspection of URL destinations, anchor mismatches, and evasion heuristics.
              </p>
            </div>
          </div>
          <div className="text-[10px] text-slate-400 bg-slate-900 px-2 py-1 rounded border border-surface-border">
            Zero-Trust Safe Inspection (No SSRF Crawling)
          </div>
        </div>

        {urls.length === 0 ? (
          <div className="text-center py-8 text-xs text-slate-400">
            No external hyperlinks detected in this email.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] font-semibold border-b border-surface-border">
                <tr>
                  <th className="py-2.5 px-3">Destination URL & Anchor</th>
                  <th className="py-2.5 px-3">Domain</th>
                  <th className="py-2.5 px-3">Protocol</th>
                  <th className="py-2.5 px-3">Risk Level</th>
                  <th className="py-2.5 px-3">Heuristic Findings</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-border">
                {urls.map((u, i) => {
                  const style = getSeverityStyle(u.risk_level);
                  return (
                    <tr
                      key={i}
                      className={`hover:bg-slate-800/40 transition-colors ${
                        u.risk >= 60 ? "bg-red-500/5" : ""
                      }`}
                    >
                      <td className="py-3 px-3 max-w-xs">
                        <div className="font-mono text-slate-200 truncate" title={u.full_url}>
                          {u.full_url}
                        </div>
                        {u.anchor_mismatch && (
                          <div className="mt-1 flex items-center gap-1 text-[10px] text-amber-400 font-bold bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20">
                            <AlertCircle className="w-3 h-3" />
                            Display Anchor Mismatch: &quot;{u.display_text}&quot;
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-3 font-mono text-slate-300">
                        {u.hostname}
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`font-mono text-[10px] px-1.5 py-0.5 rounded ${
                            u.scheme === "https"
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                              : "bg-red-500/10 text-red-400 border border-red-500/20 font-bold"
                          }`}
                        >
                          {u.scheme.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`inline-block px-2 py-0.5 rounded-full text-[10px] font-bold ${style.badge}`}
                        >
                          {u.risk_level} ({u.risk})
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-300 text-[11px]">
                        {u.reason}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Cryptocurrency Indicators */}
      {cryptoIndicators.length > 0 && (
        <div className="bg-surface border border-surface-border rounded-xl p-5">
          <div className="flex items-center gap-2.5 border-b border-surface-border pb-3 mb-3">
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400">
              <Coins className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-slate-100">
                Cryptocurrency Indicators Detected ({cryptoIndicators.length})
              </h3>
              <p className="text-[11px] text-slate-400">
                Autonomous extraction of payment addresses (e.g. Bitcoin, Ethereum).
              </p>
            </div>
          </div>

          <div className="space-y-2">
            {cryptoIndicators.map((c, idx) => (
              <div
                key={idx}
                className="p-3 rounded-lg bg-slate-900/80 border border-amber-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-amber-400">{c.currency}</span>
                    <span className="font-mono text-slate-200 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                      {c.address}
                    </span>
                  </div>
                  <div className="text-slate-400 text-[11px] mt-1 font-mono">
                    Context: {c.context}
                  </div>
                </div>
                <div className="text-[10px] text-slate-400 flex-shrink-0">
                  Indicator Observed (Analyst Review Required)
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
