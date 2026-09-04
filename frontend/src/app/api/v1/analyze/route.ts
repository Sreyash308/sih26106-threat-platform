import { NextRequest, NextResponse } from "next/server";
import { runForensicAnalysis } from "@/lib/forensic-engine";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const formData = await req.formData();
    const rawText = formData.get("raw_text") as string | null;
    const file = formData.get("file") as File | null;

    let payload = "";
    let filename = "email.eml";

    if (file) {
      payload = await file.text();
      filename = file.name || "uploaded.eml";
    } else if (rawText) {
      payload = rawText;
      filename = "pasted_email.eml";
    } else {
      return NextResponse.json(
        { success: false, error: { message: "No email file or raw text provided." } },
        { status: 400 }
      );
    }

    const result = runForensicAnalysis(payload, filename);
    return NextResponse.json(result);
  } catch (error: any) {
    return NextResponse.json(
      { success: false, error: { message: error.message || "Failed to analyze email." } },
      { status: 500 }
    );
  }
}
