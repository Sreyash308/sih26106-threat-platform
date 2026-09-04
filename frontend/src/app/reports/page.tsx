"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { FileText, FileDown, Download, ExternalLink, ShieldCheck, RefreshCw } from "lucide-react";
import { fetchInvestigations, getPDFReportUrl, getJSONExportUrl } from "@/lib/api";
import { InvestigationListItem } from "@/lib/types";
import { formatDate, getSeverityStyle } from "@/lib/utils";

export default function ReportsPage() {
  const [items, setItems] = useState<InvestigationListItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadReports();
  }, []);

  const loadReports = async () => {
    try {
      setLoading(true);
      const res = await fetchInvestigations({ limit: 50 });
      setItems(res.items || []);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-1 text-xs font-semibold text-indigo-400 uppercase tracking-wider">
          <FileText className="w-3.5 h-3.5" />
          <span>Forensic Deliverables</span>
        </div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">
          Executive & Technical Forensic Reports
        </h1>
        <p className="text-slate-400 text-xs mt-1">
          Export court-admissible and SOC-ready PDF investigation reports and full machine-readable JSON forensic archives.
        </p>
      </div>

      {/* Reports Listing Table */}
      <div className="bg-surface border border-surface-border rounded-xl overflow-hidden">
        <div className="p-4 border-b border-surface-border flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-100">
            Available Investigation Case Reports ({items.length})
          </h2>
          <button
            onClick={loadReports}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
            title="Refresh list"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        {loading ? (
          <div className="py-16 text-center text-xs text-slate-400">
            <RefreshCw className="w-6 h-6 animate-spin text-indigo-400 mx-auto mb-2" />
            Generating reports directory...
          </div>
        ) : items.length === 0 ? (
          <div className="py-16 text-center text-xs text-slate-400">
            No completed reports available. Submit an email on the Analyze page to generate one.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] font-semibold border-b border-surface-border">
                <tr>
                  <th className="py-3 px-4">Case Reference</th>
                  <th className="py-3 px-4">Subject</th>
                  <th className="py-3 px-4">Severity & Score</th>
                  <th className="py-3 px-4">Date Generated</th>
                  <th className="py-3 px-4 text-right">Download Deliverables</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-border">
                {items.map((inv) => {
                  const style = getSeverityStyle(inv.severity);
                  return (
                    <tr key={inv.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3.5 px-4 font-mono font-bold text-indigo-400">
                        {inv.id}
                      </td>
                      <td className="py-3.5 px-4 font-medium text-slate-200 max-w-sm truncate">
                        {inv.subject}
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`inline-block px-2.5 py-0.5 rounded-full text-[10px] font-bold ${style.badge}`}>
                          {inv.severity} ({inv.threat_score})
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                        {formatDate(inv.created_at)}
                      </td>
                      <td className="py-3.5 px-4 text-right space-x-2">
                        <Link
                          href={`/investigations/${inv.id}`}
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors border border-surface-border"
                        >
                          <span>View Case</span>
                          <ExternalLink className="w-3 h-3" />
                        </Link>
                        <a
                          href={getPDFReportUrl(inv.id)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-sm transition-colors"
                        >
                          <FileDown className="w-3 h-3" />
                          <span>PDF Report</span>
                        </a>
                        <a
                          href={getJSONExportUrl(inv.id)}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition-colors border border-surface-border"
                        >
                          <Download className="w-3 h-3" />
                          <span>JSON</span>
                        </a>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
