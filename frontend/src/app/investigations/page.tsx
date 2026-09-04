"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  FileSearch,
  Search,
  Filter,
  ArrowRight,
  PlusCircle,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";

import { fetchInvestigations } from "@/lib/api";
import { InvestigationListItem } from "@/lib/types";
import { formatDate, getSeverityStyle, getStatusStyle } from "@/lib/utils";

export default function InvestigationsPage() {
  const router = useRouter();

  const [items, setItems] = useState<InvestigationListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [limit] = useState(15);
  const [loading, setLoading] = useState(true);

  // Filters
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");

  useEffect(() => {
    loadCases();
  }, [page, severityFilter, statusFilter]);

  const loadCases = async () => {
    try {
      setLoading(true);
      const skip = (page - 1) * limit;
      const res = await fetchInvestigations({
        skip,
        limit,
        severity: severityFilter !== "ALL" ? severityFilter : undefined,
        status: statusFilter !== "ALL" ? statusFilter : undefined,
        search: search.trim() || undefined,
      });
      setItems(res.items || []);
      setTotal(res.total || 0);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    loadCases();
  };

  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1 text-xs font-semibold text-indigo-400 uppercase tracking-wider">
            <FileSearch className="w-3.5 h-3.5" />
            <span>Case Archive & Case Management</span>
          </div>
          <h1 className="text-2xl font-extrabold text-white tracking-tight">
            Forensic Investigations ({total})
          </h1>
          <p className="text-slate-400 text-xs mt-1">
            Searchable repository of all triaged emails, authentication findings, and persisted analyst logs.
          </p>
        </div>

        <Link
          href="/analyze"
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs shadow-glow transition-all"
        >
          <PlusCircle className="w-4 h-4" />
          <span>New Investigation</span>
        </Link>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-surface border border-surface-border rounded-xl p-4 flex flex-col md:flex-row items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="flex-1 w-full flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by Case ID, Subject, Sender, IP, or Country..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-900 border border-surface-border rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-indigo-500"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-surface-border transition-colors"
          >
            Search
          </button>
        </form>

        <div className="flex items-center gap-3 w-full md:w-auto">
          {/* Severity Filter */}
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5" />
            <span>Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-900 border border-surface-border rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="SAFE">Safe</option>
            </select>
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <span>Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-900 border border-surface-border rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
            >
              <option value="ALL">All Statuses</option>
              <option value="NEW">New</option>
              <option value="IN_PROGRESS">In Progress</option>
              <option value="REVIEWED">Reviewed</option>
              <option value="ESCALATED">Escalated</option>
              <option value="CLOSED">Closed</option>
            </select>
          </div>
        </div>
      </div>

      {/* Case Table */}
      <div className="bg-surface border border-surface-border rounded-xl overflow-hidden">
        {loading ? (
          <div className="py-16 text-center text-xs text-slate-400 space-y-2">
            <RefreshCw className="w-6 h-6 animate-spin text-indigo-400 mx-auto" />
            <div>Fetching investigation records...</div>
          </div>
        ) : items.length === 0 ? (
          <div className="py-16 text-center text-xs text-slate-400">
            No investigations match the selected filter criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/90 text-slate-400 uppercase text-[10px] font-semibold border-b border-surface-border">
                <tr>
                  <th className="py-3 px-4">Case ID</th>
                  <th className="py-3 px-4">Subject</th>
                  <th className="py-3 px-4">Sender Address</th>
                  <th className="py-3 px-4">Threat Score</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">SPF / DKIM / DMARC</th>
                  <th className="py-3 px-4">Sending Relay</th>
                  <th className="py-3 px-4">Created Date</th>
                  <th className="py-3 px-4">Case Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-border">
                {items.map((inv) => {
                  const style = getSeverityStyle(inv.severity);
                  return (
                    <tr
                      key={inv.id}
                      onClick={() => router.push(`/investigations/${inv.id}`)}
                      className="hover:bg-slate-800/60 cursor-pointer transition-colors group"
                    >
                      <td className="py-3.5 px-4 font-mono font-bold text-indigo-400 group-hover:underline">
                        {inv.id}
                      </td>
                      <td className="py-3.5 px-4 max-w-xs truncate font-medium text-slate-200">
                        {inv.subject}
                      </td>
                      <td className="py-3.5 px-4 max-w-[180px] truncate font-mono text-[11px] text-slate-400">
                        {inv.sender}
                      </td>
                      <td className="py-3.5 px-4 font-mono font-bold text-slate-100">
                        {inv.threat_score} / 100
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`inline-block px-2 py-0.5 rounded-full text-[10px] font-bold ${style.badge}`}>
                          {inv.severity}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 font-mono text-[11px]">
                        <span className={inv.spf_status === "Pass" ? "text-emerald-400" : "text-red-400"}>
                          {inv.spf_status?.[0] || "-"}
                        </span>
                        {" / "}
                        <span className={inv.dkim_status === "Pass" ? "text-emerald-400" : "text-red-400"}>
                          {inv.dkim_status?.[0] || "-"}
                        </span>
                        {" / "}
                        <span className={inv.dmarc_status === "Pass" ? "text-emerald-400" : "text-red-400"}>
                          {inv.dmarc_status?.[0] || "-"}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-slate-300">
                        <div>{inv.source_country || "Unknown"}</div>
                        <div className="font-mono text-[10px] text-slate-400">{inv.source_ip}</div>
                      </td>
                      <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                        {formatDate(inv.created_at)}
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${getStatusStyle(inv.status)}`}>
                          {inv.status}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        {total > limit && (
          <div className="p-4 border-t border-surface-border flex items-center justify-between text-xs text-slate-400">
            <div>
              Showing {(page - 1) * limit + 1} to {Math.min(page * limit, total)} of {total} cases
            </div>
            <div className="flex items-center gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage(page - 1)}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 transition-colors border border-surface-border"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="font-mono text-slate-200">
                Page {page} of {totalPages}
              </span>
              <button
                disabled={page >= totalPages}
                onClick={() => setPage(page + 1)}
                className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 transition-colors border border-surface-border"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
