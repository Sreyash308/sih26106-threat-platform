"use client";

import { useEffect, useState } from "react";
import { Globe2, MapPin, Search, Compass, Shield, Server, ArrowRight } from "lucide-react";
import RouteMap from "@/components/map/RouteMap";
import { fetchGeoIntelligence, lookupThreat } from "@/lib/api";
import { RoutingHop } from "@/lib/types";

export default function GeoIntelligencePage() {
  const [geoData, setGeoData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  // IP Explorer State
  const [ipQuery, setIpQuery] = useState("203.0.113.195");
  const [ipResult, setIpResult] = useState<any>(null);
  const [ipSearching, setIpSearching] = useState(false);

  useEffect(() => {
    loadGeo();
  }, []);

  const loadGeo = async () => {
    try {
      setLoading(true);
      const data = await fetchGeoIntelligence();
      setGeoData(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleSearchIp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ipQuery.trim()) return;
    setIpSearching(true);
    try {
      const res = await lookupThreat("ip", ipQuery.trim());
      setIpResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setIpSearching(false);
    }
  };

  // Convert points to RoutingHops for the map
  const mockHops: RoutingHop[] = (geoData?.geo_points || []).map((p: any, i: number) => ({
    hop_number: i + 1,
    from_hostname: p.city || "Relay",
    from_ip: p.ip,
    by_hostname: p.isp || "Host",
    by_ip: p.ip,
    ip_classification: "public",
    is_public: true,
    country: p.country,
    city: p.city,
    region: p.city,
    latitude: p.lat,
    longitude: p.lon,
    isp: p.isp,
    organization: p.isp,
    asn: "Observed",
    ordering_confidence: "High",
    suspicious: p.suspicious,
    evidence: "Observed relay node",
    provider_status: "demo_intelligence",
  }));

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-2 mb-1 text-xs font-semibold text-indigo-400 uppercase tracking-wider">
          <Globe2 className="w-3.5 h-3.5" />
          <span>Geographic Route Intelligence</span>
        </div>
        <h1 className="text-2xl font-extrabold text-white tracking-tight">
          Global Mail Relay & IP Telemetry
        </h1>
        <p className="text-slate-400 text-xs mt-1">
          Forensic mapping of mail transfer hops, public routing pathways, and bulletproof infrastructure locations.
        </p>
      </div>

      {/* Global Map Card */}
      <div className="bg-surface border border-surface-border rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-surface-border pb-3">
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Compass className="w-4 h-4 text-indigo-400" />
            Observed Transmission Relays Across Investigations
          </h2>
          <span className="text-xs text-indigo-400 font-mono bg-indigo-500/10 px-2.5 py-1 rounded border border-indigo-500/20">
            {mockHops.length} Active Geo Nodes Mapped
          </span>
        </div>

        <RouteMap hops={mockHops} />
      </div>

      {/* Two Column Layout: IP Explorer + Top Country Relays */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Interactive IP Intelligence Explorer */}
        <div className="bg-surface border border-surface-border rounded-xl p-5 space-y-4">
          <div className="border-b border-surface-border pb-3">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <Server className="w-4 h-4 text-indigo-400" />
              IP Forensic Classification Explorer
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Inspect any IPv4 or IPv6 address for RFC ranges (Private, CGNAT, Loopback, Documentation) and threat reputation.
            </p>
          </div>

          <form onSubmit={handleSearchIp} className="flex gap-2">
            <input
              type="text"
              placeholder="e.g. 203.0.113.195 or 192.168.1.1..."
              value={ipQuery}
              onChange={(e) => setIpQuery(e.target.value)}
              className="flex-1 bg-slate-900 border border-surface-border rounded-lg px-3 py-2 text-xs text-slate-200 font-mono placeholder-slate-400 focus:outline-none focus:border-indigo-500"
            />
            <button
              type="submit"
              disabled={ipSearching}
              className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold shadow-sm transition-colors"
            >
              {ipSearching ? "Scanning..." : "Query IP"}
            </button>
          </form>

          {ipResult && (
            <div className="p-4 rounded-xl bg-slate-900/80 border border-surface-border space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono text-indigo-400 font-bold text-sm">
                  {ipResult.ip}
                </span>
                <span className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded border border-slate-700">
                  {ipResult.data?.provider_status?.toUpperCase() || "EVALUATED"}
                </span>
              </div>
              <div className="text-slate-200 font-medium">
                Reputation:{" "}
                <span
                  className={
                    ipResult.data?.threat_score >= 50 ? "text-red-400 font-bold" : "text-emerald-400 font-bold"
                  }
                >
                  {ipResult.data?.reputation || "Neutral"}
                </span>
              </div>
              <div className="text-slate-400 text-[11px]">
                Threat Score: <span className="font-mono text-slate-200">{ipResult.data?.threat_score ?? "N/A"} / 100</span>
              </div>
              <div className="text-slate-400 text-[11px]">
                Feed Provider: <span className="text-slate-300 font-medium">{ipResult.data?.provider_name}</span>
              </div>
              {ipResult.data?.note && (
                <div className="text-[10px] text-slate-400 italic bg-slate-950 p-2 rounded border border-slate-800">
                  {ipResult.data?.note}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Top Relay Countries */}
        <div className="bg-surface border border-surface-border rounded-xl p-5 space-y-4">
          <div className="border-b border-surface-border pb-3">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <MapPin className="w-4 h-4 text-indigo-400" />
              Observed Relay Country Frequencies
            </h3>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Top countries traversed by suspicious incoming email hops.
            </p>
          </div>

          <div className="space-y-2.5">
            {geoData?.top_relay_countries?.length > 0 ? (
              geoData.top_relay_countries.map((c: any, i: number) => (
                <div
                  key={i}
                  className="flex items-center justify-between p-2.5 rounded-lg bg-slate-900/60 border border-surface-border text-xs"
                >
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-indigo-400">#{i + 1}</span>
                    <span className="font-medium text-slate-200">{c.country}</span>
                  </div>
                  <div className="font-mono text-slate-400">{c.count} Hops</div>
                </div>
              ))
            ) : (
              <div className="text-center py-6 text-xs text-slate-400">
                Awaiting telemetry...
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
