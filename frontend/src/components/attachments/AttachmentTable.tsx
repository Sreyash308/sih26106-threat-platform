"use client";

import { useState } from "react";
import { AttachmentItem } from "@/lib/types";
import { formatBytes, getSeverityStyle } from "@/lib/utils";
import { FileArchive, Copy, Check, AlertOctagon, FileWarning } from "lucide-react";

interface AttachmentTableProps {
  attachments: AttachmentItem[];
}

export default function AttachmentTable({ attachments = [] }: AttachmentTableProps) {
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const handleCopy = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="bg-surface border border-surface-border rounded-xl p-5">
      <div className="flex items-center justify-between border-b border-surface-border pb-3 mb-4">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400">
            <FileArchive className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100">
              Extracted MIME Attachments ({attachments.length})
            </h3>
            <p className="text-[11px] text-slate-400">
              Deterministic cryptographic hashing, double-extension inspection, and macro detection.
            </p>
          </div>
        </div>

        <div className="text-[10px] text-slate-400 bg-slate-900 px-2 py-1 rounded border border-surface-border">
          Zero-Execution Forensic Isolation
        </div>
      </div>

      {attachments.length === 0 ? (
        <div className="text-center py-8 text-xs text-slate-400">
          No file attachments present in this email.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] font-semibold border-b border-surface-border">
              <tr>
                <th className="py-2.5 px-3">Filename & Extension</th>
                <th className="py-2.5 px-3">File Size</th>
                <th className="py-2.5 px-3">MIME Type</th>
                <th className="py-2.5 px-3">SHA-256 Fingerprint</th>
                <th className="py-2.5 px-3">Risk Assessment</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border">
              {attachments.map((att, i) => {
                const style = getSeverityStyle(att.risk_level);
                return (
                  <tr
                    key={i}
                    className={`hover:bg-slate-800/40 transition-colors ${
                      att.suspicious ? "bg-red-500/5" : ""
                    }`}
                  >
                    <td className="py-3 px-3 max-w-xs">
                      <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                        {att.suspicious ? (
                          <AlertOctagon className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                        ) : (
                          <FileArchive className="w-3.5 h-3.5 text-slate-400 flex-shrink-0" />
                        )}
                        <span className="truncate">{att.filename}</span>
                      </div>
                      {att.double_extension && (
                        <span className="inline-block mt-1 text-[10px] bg-red-500/20 text-red-300 font-bold px-1.5 py-0.5 rounded border border-red-500/30">
                          DECEPTIVE DOUBLE EXTENSION
                        </span>
                      )}
                      {att.macro_enabled && (
                        <span className="inline-block mt-1 ml-1 text-[10px] bg-amber-500/20 text-amber-300 font-bold px-1.5 py-0.5 rounded border border-amber-500/30">
                          MACRO-ENABLED
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-3 text-slate-300 font-mono">
                      {formatBytes(att.size_bytes)}
                    </td>

                    <td className="py-3 px-3 font-mono text-slate-400 text-[11px]">
                      {att.mime_type}
                    </td>

                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1.5">
                        <span
                          className="font-mono text-[10px] text-indigo-300 bg-slate-950 px-2 py-1 rounded border border-slate-800 truncate max-w-[160px]"
                          title={att.sha256}
                        >
                          {att.sha256}
                        </span>
                        <button
                          onClick={() => handleCopy(att.sha256)}
                          title="Copy SHA-256 Hash"
                          className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                        >
                          {copiedHash === att.sha256 ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </td>

                    <td className="py-3 px-3">
                      <div className="flex flex-col items-start gap-1">
                        <span
                          className={`inline-block px-2 py-0.5 rounded-full text-[10px] font-bold ${style.badge}`}
                        >
                          {att.risk_level}
                        </span>
                        <span className="text-[10px] text-slate-400 leading-tight">
                          {att.reason}
                        </span>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
