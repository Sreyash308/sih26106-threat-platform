import { NextRequest, NextResponse } from "next/server";
import { toInvestigationDetail } from "@/lib/forensic-engine";

export const dynamic = "force-dynamic";
export const dynamicParams = true;

export async function GET(_req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const detail = toInvestigationDetail(params.id);
    if (!detail) {
      return NextResponse.json({ success: false, error: { message: "Investigation not found" } }, { status: 404 });
    }
    return new Response(JSON.stringify(detail, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Content-Disposition": `attachment; filename="forensic_report_${params.id}.json"`,
      },
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
