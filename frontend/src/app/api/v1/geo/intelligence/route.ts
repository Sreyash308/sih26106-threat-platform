import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET() {
  const points = [
    {
      ip: "203.0.113.195",
      country: "Russian Federation",
      city: "Moscow",
      lat: 55.7558,
      lon: 37.6173,
      isp: "Bulletproof Transit AS64512",
      suspicious: true,
      investigations_count: 4,
    },
    {
      ip: "198.51.100.88",
      country: "United Kingdom",
      city: "London",
      lat: 51.5074,
      lon: -0.1278,
      isp: "Enterprise Gateway Exchange",
      suspicious: false,
      investigations_count: 6,
    },
    {
      ip: "198.51.100.25",
      country: "Germany",
      city: "Frankfurt",
      lat: 50.1109,
      lon: 8.6821,
      isp: "Hetzner Cloud Node",
      suspicious: false,
      investigations_count: 3,
    },
    {
      ip: "198.51.100.12",
      country: "United States",
      city: "Ashburn",
      lat: 39.0438,
      lon: -77.4874,
      isp: "AWS US-East",
      suspicious: false,
      investigations_count: 8,
    },
    {
      ip: "192.0.2.1",
      country: "United States",
      city: "San Jose",
      lat: 37.3382,
      lon: -121.8863,
      isp: "Workstation Access Dynamic",
      suspicious: true,
      investigations_count: 2,
    },
  ];

  return NextResponse.json({
    geo_points: points,
    total_unique_ips: points.length,
    countries_represented: ["Russian Federation", "United Kingdom", "Germany", "United States"],
  });
}
