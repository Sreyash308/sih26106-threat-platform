"use client";

import { useState, useMemo } from "react";
import { Code2, Copy, Check, Search, ChevronDown, ChevronUp } from "lucide-react";

interface HeaderViewerProps {
  rawHeaders: string;
  rawHtml?: string;
  plainText?: string;
}

export default function HeaderViewer({ rawHeaders, rawHtml, plainText }: HeaderViewerProps) {
  const [activeTab, setActiveTab] = useState<"headers" | "text" | "html">("headers");
  const [copied, setCopied] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [isExpanded, setIsExpanded] = useState(false);

  const handleCopy = () => {
    const textToCopy =
      activeTab === "headers" ? rawHeaders : activeTab === "text" ? plainText || "" : rawHtml || "";
    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const filteredLines = useMemo(() => {
    if (!rawHeaders) return [];
    const lines = rawHeaders.split("\n");
    if (!searchTerm.trim()) return lines;
    const lower = searchTerm.toLowerCase();
    return lines.filter((l) => l.toLowerCase().includes(lower));
  }, [rawHeaders, searchTerm]);

  return (
    <div className="bg-surface border border-surface-border rounded-xl p-5 space-y-4">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-surface-border pb-3">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab("headers")}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              activeTab === "headers"
                ? "bg-indigo-600 text-white shadow-sm"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"
            }`}
          >
            Raw Headers
          </button>
          <button
            onClick={() => setActiveTab("text")}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              activeTab === "text"
                ? "bg-indigo-600 text-white shadow-sm"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"
            }`}
          >
            Extracted Plain Text
          </button>
          <button
            onClick={() => setActiveTab("html")}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              activeTab === "html"
                ? "bg-indigo-600 text-white shadow-sm"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800"
            }`}
          >
            Sanitized HTML Preview
          </button>
        </div>

        <div className="flex items-center gap-2">
          {activeTab === "headers" && (
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Filter headers..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="bg-slate-900 border border-surface-border rounded-md pl-8 pr-3 py-1 text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-indigo-500 w-44"
              />
            </div>
          )}

          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors border border-surface-border"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? "Copied" : "Copy"}</span>
          </button>

          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors border border-surface-border"
            title={isExpanded ? "Collapse" : "Expand"}
          >
            {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* Content Display Box */}
      <div
        className={`bg-slate-950 rounded-lg p-4 font-mono text-xs overflow-auto border border-surface-border transition-all ${
          isExpanded ? "max-h-[650px]" : "max-h-[300px]"
        }`}
      >
        {activeTab === "headers" && (
          <div className="space-y-1 text-slate-300 leading-relaxed select-text">
            {filteredLines.map((line, idx) => {
              const isSecurityHeader = line.match(
                /^(Received|Authentication-Results|Received-SPF|DKIM-Signature|ARC-|X-Originating-IP|Return-Path|From):/i
              );
              return (
                <div
                  key={idx}
                  className={`${
                    isSecurityHeader
                      ? "text-indigo-300 font-semibold bg-indigo-500/5 px-1 rounded"
                      : "text-slate-400"
                  } hover:bg-slate-900 px-1 rounded`}
                >
                  {line}
                </div>
              );
            })}
          </div>
        )}

        {activeTab === "text" && (
          <pre className="whitespace-pre-wrap text-slate-200 leading-relaxed font-mono">
            {plainText || "(No plain-text extracted)"}
          </pre>
        )}

        {activeTab === "html" && (
          <div className="bg-white text-slate-900 p-4 rounded border border-slate-300 font-sans">
            <div className="text-[11px] text-amber-700 bg-amber-50 p-2 rounded mb-3 border border-amber-200">
              Safe Sandboxed View: Active scripts, event handlers, and remote frames have been stripped.
            </div>
            <div
              dangerouslySetInnerHTML={{ __html: rawHtml || "<p>No HTML payload present.</p>" }}
            />
          </div>
        )}
      </div>
    </div>
  );
}
