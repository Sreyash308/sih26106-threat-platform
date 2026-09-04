"use client";

import { useState, useRef } from "react";
import { useRouter } from "next/navigation";
import {
  UploadCloud,
  FileText,
  Crosshair,
  Trash2,
  Flame,
  CheckCircle2,
  AlertCircle,
  ShieldAlert,
  Loader2,
  Sparkles,
} from "lucide-react";
import { analyzeEmailPayload } from "@/lib/api";
import { DEMO_EMAILS } from "@/data/demo_emails";

export default function AnalyzePage() {
  const router = useRouter();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [activeTab, setActiveTab] = useState<"upload" | "paste">("upload");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [pastedText, setPastedText] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [progressStep, setProgressStep] = useState("");

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const validateAndSetFile = (file: File) => {
    setErrorMessage("");
    // Check extension
    const ext = file.name.split(".").pop()?.toLowerCase();
    if (ext !== "eml" && ext !== "txt" && ext !== "msg") {
      setErrorMessage("Please upload an email file with .eml, .txt, or .msg extension.");
      return;
    }
    // Check file size (10 MB limit)
    if (file.size > 10 * 1024 * 1024) {
      setErrorMessage("File exceeds the maximum 10 MB forensic ingestion limit.");
      return;
    }
    setSelectedFile(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleLoadDemo = (demoId: string) => {
    const demo = DEMO_EMAILS.find((d) => d.id === demoId);
    if (demo) {
      setPastedText(demo.raw);
      setActiveTab("paste");
      setSelectedFile(null);
      setErrorMessage("");
    }
  };

  const handleClear = () => {
    setSelectedFile(null);
    setPastedText("");
    setErrorMessage("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const handleSubmitAnalysis = async () => {
    setErrorMessage("");

    if (activeTab === "upload" && !selectedFile) {
      setErrorMessage("Please select or drop an .eml file to analyze.");
      return;
    }
    if (activeTab === "paste" && !pastedText.trim()) {
      setErrorMessage("Please paste raw RFC 2822 email content or headers.");
      return;
    }

    setIsAnalyzing(true);
    setProgressStep("Initializing forensic parser & extracting MIME structure...");

    try {
      const formData = new FormData();
      if (activeTab === "upload" && selectedFile) {
        formData.append("file", selectedFile);
      } else {
        formData.append("raw_text", pastedText);
      }

      setTimeout(() => setProgressStep("Evaluating SPF, DKIM, and DMARC alignment..."), 400);
      setTimeout(() => setProgressStep("Tracing network relay hops & resolving geolocation..."), 800);
      setTimeout(() => setProgressStep("Running NLP social engineering and threat scoring engine..."), 1200);

      const result = await analyzeEmailPayload(formData);
      router.push(`/investigations/${result.summary.investigation_id}`);
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to complete email threat analysis.");
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Page Title */}
      <div>
        <div className="flex items-center gap-2 mb-1 text-xs font-semibold text-indigo-400 uppercase tracking-wider">
          <Crosshair className="w-3.5 h-3.5" />
          <span>Forensic Ingestion Gateway</span>
        </div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">
          Analyze Suspicious Email
        </h1>
        <p className="text-slate-400 text-xs mt-1">
          Upload or paste an email for forensic analysis. Multi-layer inspection across authentication, routing hops, heuristics, and explainable AI scoring.
        </p>
      </div>

      {/* Synthetic Demo Lure Presets */}
      <div className="bg-surface border border-surface-border rounded-xl p-4">
        <div className="flex items-center justify-between mb-2.5">
          <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            Quick-Load Synthetic Demonstration Samples
          </span>
          <span className="text-[10px] text-slate-400">Safe Test Payloads</span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2">
          {DEMO_EMAILS.map((demo) => (
            <button
              key={demo.id}
              onClick={() => handleLoadDemo(demo.id)}
              className="p-2 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-surface-border hover:border-indigo-500/50 text-left transition-all group"
            >
              <div className="text-[11px] font-bold text-slate-200 group-hover:text-indigo-300 truncate">
                {demo.name.split("(")[0]}
              </div>
              <div className="text-[10px] text-slate-400 mt-0.5">{demo.category}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Input Selection Tabs */}
      <div className="bg-surface border border-surface-border rounded-xl p-6 space-y-6">
        <div className="flex border-b border-surface-border gap-6">
          <button
            onClick={() => setActiveTab("upload")}
            className={`pb-3 text-xs font-bold flex items-center gap-2 transition-all relative ${
              activeTab === "upload" ? "text-indigo-400" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <UploadCloud className="w-4 h-4" />
            <span>Upload .EML File</span>
            {activeTab === "upload" && (
              <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500 rounded-full" />
            )}
          </button>

          <button
            onClick={() => setActiveTab("paste")}
            className={`pb-3 text-xs font-bold flex items-center gap-2 transition-all relative ${
              activeTab === "paste" ? "text-indigo-400" : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>Paste Raw Email / Headers</span>
            {activeTab === "paste" && (
              <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-indigo-500 rounded-full" />
            )}
          </button>
        </div>

        {/* Tab 1: Drag & Drop File */}
        {activeTab === "upload" && (
          <div>
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-8 flex flex-col items-center justify-center text-center cursor-pointer transition-all ${
                dragOver
                  ? "border-indigo-500 bg-indigo-500/10"
                  : selectedFile
                  ? "border-emerald-500/50 bg-emerald-500/5"
                  : "border-surface-border hover:border-slate-600 bg-slate-900/40"
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml,.txt,.msg"
                onChange={handleFileChange}
                className="hidden"
              />

              {selectedFile ? (
                <div className="space-y-2">
                  <div className="w-12 h-12 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center mx-auto">
                    <CheckCircle2 className="w-6 h-6" />
                  </div>
                  <div className="font-bold text-sm text-slate-100">{selectedFile.name}</div>
                  <div className="text-xs text-slate-400">
                    {(selectedFile.size / 1024).toFixed(1)} KB • Ready for deep forensic parsing
                  </div>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleClear();
                    }}
                    className="text-xs text-red-400 hover:text-red-300 font-medium inline-block mt-2"
                  >
                    Remove File
                  </button>
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="w-12 h-12 rounded-full bg-indigo-500/10 text-indigo-400 flex items-center justify-center mx-auto">
                    <UploadCloud className="w-6 h-6" />
                  </div>
                  <div className="font-bold text-sm text-slate-200">
                    Drag and drop your .eml file here, or browse
                  </div>
                  <div className="text-xs text-slate-400 max-w-sm">
                    Supports RFC 2822 standard email exports from Outlook, Gmail, Thunderbird, and mail relays (max 10 MB).
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab 2: Paste Raw Text */}
        {activeTab === "paste" && (
          <div className="space-y-2">
            <textarea
              rows={12}
              placeholder="Paste raw email message with headers (From:, To:, Received:, Subject:, Date:)..."
              value={pastedText}
              onChange={(e) => setPastedText(e.target.value)}
              className="w-full bg-slate-950 border border-surface-border rounded-xl p-4 font-mono text-xs text-slate-200 placeholder-slate-400 focus:outline-none focus:border-indigo-500 transition-colors resize-y leading-relaxed"
            />
            <div className="text-[11px] text-slate-400 flex justify-between">
              <span>Plain text input automatically parses RFC 2047 headers & MIME boundaries.</span>
              <span>{pastedText.length} characters</span>
            </div>
          </div>
        )}

        {/* Error Alert */}
        {errorMessage && (
          <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-xs text-red-400 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        {/* Progress Display */}
        {isAnalyzing && (
          <div className="p-4 rounded-xl bg-slate-900 border border-indigo-500/30 space-y-2">
            <div className="flex items-center gap-3 text-xs font-semibold text-indigo-300">
              <Loader2 className="w-4 h-4 animate-spin text-indigo-400" />
              <span>{progressStep}</span>
            </div>
            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div className="h-full bg-indigo-500 rounded-full animate-pulse w-3/4" />
            </div>
          </div>
        )}

        {/* Actions Bar */}
        <div className="flex items-center justify-between pt-2 border-t border-surface-border">
          <button
            type="button"
            onClick={handleClear}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 text-xs font-medium transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear Input</span>
          </button>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => handleLoadDemo("phishing-ms365")}
              className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-surface-border flex items-center gap-1.5 transition-colors"
            >
              <Flame className="w-3.5 h-3.5 text-orange-400" />
              <span>Load Phishing Demo</span>
            </button>

            <button
              type="button"
              disabled={isAnalyzing}
              onClick={handleSubmitAnalysis}
              className="px-6 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-bold shadow-glow flex items-center gap-2 transition-all cursor-pointer"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Processing Forensics...</span>
                </>
              ) : (
                <>
                  <Crosshair className="w-4 h-4" />
                  <span>Analyze Threat</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Privacy Notice */}
      <div className="text-center text-[11px] text-slate-400 p-3 bg-slate-950/40 rounded-lg border border-surface-border">
        Privacy & Compliance: Email data may contain confidential or sensitive information. Analyze only authorized emails. Ingestion pipeline strips remote active scripts and does not initiate outbound URL crawling.
      </div>
    </div>
  );
}
