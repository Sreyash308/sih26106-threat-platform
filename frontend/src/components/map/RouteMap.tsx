"use client";

import dynamic from "next/dynamic";
import { RoutingHop, RouteStats } from "@/lib/types";
import { MapPin, Navigation, Compass, Layers } from "lucide-react";

// Dynamic import with ssr: false prevents "window is not defined" error in Next.js App Router
const DynamicLeafletInnerMap = dynamic(
  () => import("./LeafletInnerMap"),
  {
    ssr: false,
    loading: () => (
      <div className="w-full h-[400px] rounded-lg bg-slate-900/60 border border-surface-border flex flex-col items-center justify-center text-center p-6 animate-pulse">
        <Compass className="w-8 h-8 text-indigo-400 animate-spin mb-2" />
        <span className="text-xs text-slate-400">Loading Geospatial Route Engine...</span>
      </div>
    ),
  }
);

interface RouteMapProps {
  hops: RoutingHop[];
  stats?: RouteStats;
}

export default function RouteMap({ hops, stats }: RouteMapProps) {
  return (
    <div className="space-y-4">
      {/* Route Statistics Bar */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-900/60 border border-surface-border p-3 rounded-lg text-xs">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-md bg-indigo-500/10 text-indigo-400">
              <Layers className="w-4 h-4" />
            </div>
            <div>
              <div className="text-slate-400 text-[10px]">Total Hops</div>
              <div className="font-bold text-slate-100">{stats.total_hops} ({stats.public_hops} Public)</div>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-md bg-purple-500/10 text-purple-400">
              <MapPin className="w-4 h-4" />
            </div>
            <div>
              <div className="text-slate-400 text-[10px]">Countries Traversed</div>
              <div className="font-bold text-slate-100">
                {stats.countries_traversed.length > 0
                  ? stats.countries_traversed.join(", ")
                  : "None / Local"}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-md bg-cyan-500/10 text-cyan-400">
              <Navigation className="w-4 h-4" />
            </div>
            <div>
              <div className="text-slate-400 text-[10px]">Approx. Flight Path</div>
              <div className="font-bold text-slate-100">{stats.approximate_distance_km.toLocaleString()} km</div>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-md bg-amber-500/10 text-amber-400">
              <Compass className="w-4 h-4" />
            </div>
            <div>
              <div className="text-slate-400 text-[10px]">Longest Hop Jump</div>
              <div className="font-bold text-slate-100">{stats.longest_jump_km.toLocaleString()} km</div>
            </div>
          </div>
        </div>
      )}

      {/* Interactive Map */}
      <DynamicLeafletInnerMap hops={hops} />
    </div>
  );
}
