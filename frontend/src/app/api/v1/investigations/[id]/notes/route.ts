import { NextRequest, NextResponse } from "next/server";
import { addNote } from "@/lib/forensic-engine";

export async function POST(req: NextRequest, { params }: { params: { id: string } }) {
  try {
    const body = await req.json();
    const { author, note } = body;
    if (!note) {
      return NextResponse.json({ success: false, error: { message: "Note text is required." } }, { status: 400 });
    }
    const createdNote = addNote(params.id, author || "SOC Analyst", note);
    return NextResponse.json(createdNote);
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { message: error.message || "Failed to add analyst note" } },
      { status: 500 }
    );
  }
}
