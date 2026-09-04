import { NextRequest, NextResponse } from "next/server";
import { getInvestigationsList } from "@/lib/forensic-engine";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const skip = searchParams.get("skip") ? parseInt(searchParams.get("skip")!, 10) : 0;
    const limit = searchParams.get("limit") ? parseInt(searchParams.get("limit")!, 10) : 20;
    const severity = searchParams.get("severity") || undefined;
    const status = searchParams.get("status") || undefined;
    const search = searchParams.get("search") || undefined;

    const data = getInvestigationsList({ skip, limit, severity, status, search });
    return NextResponse.json(data);
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { message: error.message || "Failed to load investigations" } },
      { status: 500 }
    );
  }
}
