import { NextRequest, NextResponse } from "next/server";
import { updateStatus } from "@/lib/forensic-engine";

export const dynamic = "force-dynamic";
export const dynamicParams = true;

export async function PATCH(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const body = await req.json();
    const { status } = body;
    if (!status) {
      return NextResponse.json({ success: false, error: { message: "Status is required." } }, { status: 400 });
    }
    const updated = updateStatus(params.id, status);
    if (!updated) {
      return NextResponse.json({ success: false, error: { message: `Investigation ${params.id} not found.` } }, { status: 404 });
    }
    return NextResponse.json({ success: true });
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { message: error.message || "Failed to update status" } },
      { status: 500 }
    );
  }
}
