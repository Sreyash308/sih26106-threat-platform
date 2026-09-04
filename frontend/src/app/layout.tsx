import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "@/components/common/Sidebar";
import Header from "@/components/common/Header";

export const metadata: Metadata = {
  title: "SIH26106 | AI-Powered Email Threat Detection & Forensic Platform",
  description:
    "Next-generation email forensic parser, SPF/DKIM/DMARC analyzer, network hop geolocation tracer, and explainable AI threat intelligence system.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-background text-slate-100 min-h-screen antialiased flex selection:bg-indigo-500/30 selection:text-indigo-200">
        <Sidebar />
        <div className="flex-1 flex flex-col pl-64 min-w-0">
          <Header />
          <main className="flex-1 p-6 md:p-8 max-w-7xl w-full mx-auto">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
