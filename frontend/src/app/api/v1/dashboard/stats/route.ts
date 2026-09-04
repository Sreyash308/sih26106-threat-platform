import { NextResponse } from "next/server";
import { getDashboardStats } from "@/lib/forensic-engine";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const stats = getDashboardStats();
    return NextResponse.json({ success: true, data: stats });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { message: error.message || "Failed to load dashboard statistics" } },
      { status: 500 }
    );
  }
}
