"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  ShieldAlert,
  ArrowLeft,
  FileDown,
  Download,
  CheckCircle2,
  Clock,
  Send,
  User,
  ExternalLink,
  Layers,
  MapPin,
  RefreshCw,
  AlertCircle,
  Hash,
} from "lucide-react";

import { fetchInvestigation, updateInvestigationStatus } from "@/lib/api";
import { InvestigationDetail } from "@/lib/types";
import { formatDate, getSeverityStyle, getStatusStyle } from "@/lib/utils";
import { exportInvestigationPDF, exportInvestigationJSON } from "@/lib/report-export";

import ThreatGauge from "@/components/threat/ThreatGauge";
import AuthCards from "@/components/authentication/AuthCards";
import SenderCard from "@/components/threat/SenderCard";
import RouteMap from "@/components/map/RouteMap";
import UrlTable from "@/components/urls/UrlTable";
import AttachmentTable from "@/components/attachments/AttachmentTable";
import NLPReportCard from "@/components/nlp/NLPReportCard";
import ForensicTimeline from "@/components/investigations/ForensicTimeline";
import HeaderViewer from "@/components/common/HeaderViewer";
import AnalystNotes from "@/components/investigations/AnalystNotes";

export default function InvestigationDetailPage() {
  const params = useParams();
  const router = useRouter();
  const id = params?.id as string;

  const [investigation, setInvestigation] = useState<InvestigationDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<
    "overview" | "routing" | "urls" | "attachments" | "nlp" | "headers" | "notes"
  >("overview");

  useEffect(() => {
    if (id) {
      loadInvestigation();
    }
  }, [id]);

  const loadInvestigation = async () => {
    try {
      setLoading(true);
      const data = await fetchInvestigation(id);
      setInvestigation(data);
    } catch (err: any) {
      setError(err.message || "Failed to retrieve investigation case.");
    } finally {
      setLoading(false);
    }
  };

  const handleQuickMarkReviewed = async () => {
    if (!investigation) return;
    try {
      await updateInvestigationStatus(investigation.id, "REVIEWED");
      setInvestigation({ ...investigation, status: "REVIEWED" });
    } catch (err) {
      console.error(err);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
        <div className="w-10 h-10 border-4 border-indigo-500/20 border-t-indigo-500 rounded-full animate-spin" />
        <p className="text-xs text-slate-400 font-mono">Loading Forensic Case Dossier {id}...</p>
      </div>
    );
  }

  if (error || !investigation) {
    return (
      <div className="max-w-2xl mx-auto my-12 p-6 rounded-xl bg-red-500/10 border border-red-500/30 text-center space-y-4">
        <AlertCircle className="w-8 h-8 text-red-400 mx-auto" />
        <h2 className="text-base font-bold text-slate-100">Case Dossier Unavailable</h2>
        <p className="text-xs text-slate-300">{error || "Investigation record not found."}</p>
        <Link
          href="/investigations"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Return to Cases</span>
        </Link>
      </div>
    );
  }

  const analysis = investigation.analysis;
  const sevStyle = getSeverityStyle(investigation.severity);

  return (
    <div className="space-y-6">
      {/* Top Breadcrumb & Quick Actions Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-surface-border pb-4">
        <div className="flex items-center gap-3">
          <Link
            href="/investigations"
            className="p-2 rounded-lg bg-surface hover:bg-slate-800 border border-surface-border text-slate-400 hover:text-slate-200 transition-colors"
            title="Back to Investigation History"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-xs text-indigo-400">
                {investigation.id}
              </span>
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${getStatusStyle(investigation.status)}`}>
                {investigation.status}
              </span>
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${sevStyle.badge}`}>
                {investigation.severity}
              </span>
            </div>
            <h1 className="text-lg font-bold text-white mt-0.5 max-w-2xl truncate">
              {investigation.subject}
            </h1>
          </div>
        </div>

        {/* Action Buttons: PDF, JSON, Mark Reviewed */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleQuickMarkReviewed}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-surface-border text-slate-300 text-xs font-semibold transition-colors"
          >
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Mark Reviewed</span>
          </button>

          <button
            onClick={() => investigation && exportInvestigationPDF(investigation)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-sm transition-colors cursor-pointer"
          >
            <FileDown className="w-3.5 h-3.5" />
            <span>Export PDF Report</span>
          </button>

          <button
            onClick={() => investigation && exportInvestigationJSON(investigation)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-surface-border text-slate-300 text-xs font-semibold transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>JSON</span>
          </button>
        </div>
      </div>

      {/* Metadata Overview Ribbon */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-surface border border-surface-border p-4 rounded-xl text-xs">
        <div>
          <span className="text-slate-400 text-[10px] uppercase font-semibold">Sender (From)</span>
          <div className="text-slate-200 font-mono mt-0.5 truncate" title={investigation.sender}>
            {investigation.sender || "None declared"}
          </div>
        </div>
        <div>
          <span className="text-slate-400 text-[10px] uppercase font-semibold">Recipient (To)</span>
          <div className="text-slate-200 font-mono mt-0.5 truncate" title={investigation.recipient}>
            {investigation.recipient || "None declared"}
          </div>
        </div>
        <div>
          <span className="text-slate-400 text-[10px] uppercase font-semibold">Observed Sending Relay</span>
          <div className="text-slate-200 mt-0.5 flex items-center gap-1.5">
            <span className="font-mono text-indigo-300">{investigation.source_ip}</span>
            <span className="text-slate-400">({investigation.source_country})</span>
          </div>
        </div>
        <div>
          <span className="text-slate-400 text-[10px] uppercase font-semibold">Transmission Date</span>
          <div className="text-slate-200 mt-0.5">{formatDate(investigation.email_date)}</div>
        </div>
      </div>

      {/* Section Navigation Tabs */}
      <div className="flex border-b border-surface-border gap-2 overflow-x-auto text-xs font-semibold">
        {[
          { id: "overview", label: "Threat Summary & Auth" },
          { id: "routing", label: `Network Route & Map (${analysis?.routing_hops?.length || 0})` },
          { id: "urls", label: `URLs & Crypto (${analysis?.urls?.length || 0})` },
          { id: "attachments", label: `Attachments (${analysis?.attachments?.length || 0})` },
          { id: "nlp", label: "AI/NLP Social Engineering" },
          { id: "headers", label: "Raw Headers & Source" },
          { id: "notes", label: `Analyst Log (${investigation.notes?.length || 0})` },
        ].map((t) => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id as any)}
            className={`px-4 py-2.5 rounded-t-lg transition-all border-b-2 whitespace-nowrap ${
              activeTab === t.id
                ? "border-indigo-500 text-indigo-400 bg-surface/60 font-bold"
                : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/40"
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* TAB CONTENT PANELS */}

      {/* TAB 1: OVERVIEW & AUTHENTICATION */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          <ThreatGauge
            score={investigation.threat_score}
            severity={investigation.severity}
            verdict={analysis?.summary?.verdict || investigation.summary}
            subScores={analysis?.sub_scores}
            factors={analysis?.threat_factors}
          />

          {analysis?.authentication && <AuthCards auth={analysis.authentication} />}

          {analysis?.sender_analysis && <SenderCard sender={analysis.sender_analysis} />}

          {analysis?.timeline && <ForensicTimeline events={analysis.timeline} />}
        </div>
      )}

      {/* TAB 2: ROUTING & MAP */}
      {activeTab === "routing" && (
        <div className="space-y-6">
          <div className="bg-surface border border-surface-border rounded-xl p-5">
            <h3 className="text-sm font-bold text-slate-100 mb-1">
              Geographic Route & Reconstructed Transmission Path
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Visualizes the sequence of hops from origin client/relay to the destination mail exchange.
            </p>

            <RouteMap hops={analysis?.routing_hops || []} stats={analysis?.route_stats} />
          </div>

          {/* Detailed Hop Table */}
          <div className="bg-surface border border-surface-border rounded-xl p-5">
            <h3 className="text-sm font-bold text-slate-100 mb-3">
              Reconstructed Transmission Hops Table
            </h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] font-semibold border-b border-surface-border">
                  <tr>
                    <th className="py-2.5 px-3">Hop</th>
                    <th className="py-2.5 px-3">Relay Host / IP</th>
                    <th className="py-2.5 px-3">Classification</th>
                    <th className="py-2.5 px-3">Geolocation</th>
                    <th className="py-2.5 px-3">ISP / ASN</th>
                    <th className="py-2.5 px-3">Confidence</th>
                    <th className="py-2.5 px-3">Provider</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-surface-border">
                  {analysis?.routing_hops?.map((hop) => (
                    <tr key={hop.hop_number} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-3 font-mono font-bold text-indigo-400">
                        #{hop.hop_number}
                      </td>
                      <td className="py-3 px-3 max-w-xs font-mono">
                        <div className="text-slate-200 font-semibold">{hop.from_hostname || "None"}</div>
                        <div className="text-indigo-300 text-[11px]">{hop.from_ip || hop.by_ip || "Unknown IP"}</div>
                      </td>
                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px] border border-slate-700">
                          {hop.ip_classification.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-300">
                        {hop.city}, {hop.country}
                      </td>
                      <td className="py-3 px-3 text-slate-400">
                        <div>{hop.isp || "Unknown"}</div>
                        <div className="text-[10px] font-mono text-slate-500">{hop.asn}</div>
                      </td>
                      <td className="py-3 px-3">
                        <span className="text-[10px] text-slate-300 bg-slate-900 px-2 py-0.5 rounded border border-surface-border">
                          {hop.ordering_confidence}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-400 text-[10px]">
                        {hop.provider_status}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: URLS & CRYPTO */}
      {activeTab === "urls" && (
        <UrlTable
          urls={analysis?.urls || []}
          cryptoIndicators={analysis?.crypto_indicators || []}
        />
      )}

      {/* TAB 4: ATTACHMENTS */}
      {activeTab === "attachments" && (
        <AttachmentTable attachments={analysis?.attachments || []} />
      )}

      {/* TAB 5: AI / NLP */}
      {activeTab === "nlp" && analysis?.nlp_analysis && (
        <NLPReportCard nlp={analysis.nlp_analysis} />
      )}

      {/* TAB 6: RAW HEADERS & PREVIEW */}
      {activeTab === "headers" && (
        <HeaderViewer
          rawHeaders={investigation.raw_headers || analysis?.raw?.headers || ""}
          plainText={analysis?.extracted_text_preview}
          rawHtml={analysis?.sanitized_html_preview}
        />
      )}

      {/* TAB 7: ANALYST NOTES & LOG */}
      {activeTab === "notes" && (
        <AnalystNotes
          investigationId={investigation.id}
          initialStatus={investigation.status}
          initialNotes={investigation.notes || []}
          onStatusChange={(s) => setInvestigation({ ...investigation, status: s as any })}
        />
      )}
    </div>
  );
}
