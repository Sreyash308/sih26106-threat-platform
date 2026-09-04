"use client";

import { useEffect, useMemo } from "react";
import { MapContainer, TileLayer, Marker, Popup, Polyline, useMap } from "react-leaflet";
import L from "leaflet";
import { RoutingHop } from "@/lib/types";

// Auto-fit map bounds to markers
function MapBoundsUpdater({ coords }: { coords: [number, number][] }) {
  const map = useMap();
  useEffect(() => {
    if (coords.length > 0) {
      const bounds = L.latLngBounds(coords.map((c) => L.latLng(c[0], c[1])));
      map.fitBounds(bounds, { padding: [40, 40], maxZoom: 6 });
    }
  }, [coords, map]);
  return null;
}

// Create custom SVG numbered marker
function createNumberedMarker(number: number, isSuspicious: boolean) {
  const bg = isSuspicious ? "#ef4444" : "#4f46e5";
  const border = isSuspicious ? "#b91c1c" : "#312e81";
  const svg = `
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 42" width="30" height="40">
      <path d="M16 0C7.16 0 0 7.16 0 16c0 10.62 14.28 24.62 14.89 25.22a1.5 1.5 0 0 0 2.22 0C17.72 40.62 32 26.62 32 16 32 7.16 24.84 0 16 0z" fill="${bg}" stroke="${border}" stroke-width="1.5"/>
      <circle cx="16" cy="16" r="10" fill="#ffffff"/>
      <text x="16" y="20" font-size="11" font-weight="bold" fill="#0f172a" text-anchor="middle" font-family="Arial">${number}</text>
    </svg>
  `;
  return L.divIcon({
    html: svg,
    className: "custom-leaflet-marker",
    iconSize: [30, 40],
    iconAnchor: [15, 40],
    popupAnchor: [0, -38],
  });
}

interface LeafletInnerMapProps {
  hops: RoutingHop[];
}

export default function LeafletInnerMap({ hops }: LeafletInnerMapProps) {
  // Filter hops with valid numeric coordinates
  const validHops = useMemo(() => {
    return hops.filter(
      (h) =>
        typeof h.latitude === "number" &&
        typeof h.longitude === "number" &&
        !isNaN(h.latitude) &&
        !isNaN(h.longitude)
    );
  }, [hops]);

  const coords = useMemo(() => {
    return validHops.map((h) => [h.latitude as number, h.longitude as number] as [number, number]);
  }, [validHops]);

  if (coords.length === 0) {
    return (
      <div className="w-full h-80 rounded-lg bg-slate-900/60 border border-surface-border flex flex-col items-center justify-center text-center p-6">
        <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center text-slate-400 mb-3">
          🌐
        </div>
        <div className="text-sm font-semibold text-slate-300">Geographic Route Coordinates Unavailable</div>
        <div className="text-xs text-slate-400 max-w-sm mt-1">
          Observed transmission relays did not expose public routable coordinates, or internal RFC 1918 private network addresses were utilized.
        </div>
      </div>
    );
  }

  const initialCenter = coords[0] || [20, 0];

  return (
    <div className="w-full h-[400px] rounded-lg overflow-hidden border border-surface-border relative glow-border">
      <MapContainer
        center={initialCenter}
        zoom={2}
        scrollWheelZoom={false}
        className="w-full h-full"
      >
        {/* OpenStreetMap Dark CartoDB Tiles */}
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
        />

        {/* Transmission Route Polyline */}
        {coords.length > 1 && (
          <Polyline
            positions={coords}
            pathOptions={{
              color: "#6366f1",
              weight: 3,
              dashArray: "6, 8",
              opacity: 0.85,
            }}
          />
        )}

        {/* Numbered Hop Markers */}
        {validHops.map((hop) => (
          <Marker
            key={hop.hop_number}
            position={[hop.latitude as number, hop.longitude as number]}
            icon={createNumberedMarker(hop.hop_number, hop.suspicious)}
          >
            <Popup>
              <div className="p-1 min-w-[200px] text-xs">
                <div className="flex items-center justify-between border-b border-slate-700 pb-1.5 mb-1.5">
                  <span className="font-bold text-indigo-400">Hop #{hop.hop_number}</span>
                  <span className="text-[10px] bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded border border-slate-700">
                    {hop.ip_classification.toUpperCase()}
                  </span>
                </div>
                <div className="space-y-1 text-slate-200">
                  <div>
                    <span className="text-slate-400">IP:</span>{" "}
                    <span className="font-mono text-indigo-300">{hop.from_ip || hop.by_ip || "Unknown"}</span>
                  </div>
                  <div>
                    <span className="text-slate-400">Location:</span> {hop.city}, {hop.country}
                  </div>
                  <div>
                    <span className="text-slate-400">ISP:</span> {hop.isp || "Unknown"}
                  </div>
                  <div>
                    <span className="text-slate-400">ASN:</span> {hop.asn || "Unknown"}
                  </div>
                  {hop.timestamp && (
                    <div>
                      <span className="text-slate-400">Time:</span> {hop.timestamp}
                    </div>
                  )}
                  <div className="pt-1 border-t border-slate-800 text-[10px] text-slate-400">
                    Source: <span className="text-slate-300 font-medium">{hop.provider_status}</span>
                  </div>
                </div>
              </div>
            </Popup>
          </Marker>
        ))}

        <MapBoundsUpdater coords={coords} />
      </MapContainer>
    </div>
  );
}
