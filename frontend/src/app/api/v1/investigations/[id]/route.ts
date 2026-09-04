import { NextRequest, NextResponse } from "next/server";
import { toInvestigationDetail, deleteInvestigationById } from "@/lib/forensic-engine";

export const dynamic = "force-dynamic";
export const dynamicParams = true;

export async function GET(_req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const detail = toInvestigationDetail(params.id);
    if (!detail) {
      return NextResponse.json(
        { success: false, error: { message: `Investigation ${params.id} not found.` } },
        { status: 404 }
      );
    }
    return NextResponse.json({ success: true, data: detail });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { message: error.message || "Failed to load investigation" } },
      { status: 500 }
    );
  }
}

export async function DELETE(_req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const deleted = deleteInvestigationById(params.id);
    if (!deleted) {
      return NextResponse.json(
        { success: false, error: { message: `Investigation ${params.id} not found.` } },
        { status: 404 }
      );
    }
    return NextResponse.json({ success: true });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { message: error.message || "Failed to delete investigation" } },
      { status: 500 }
    );
  }
}
