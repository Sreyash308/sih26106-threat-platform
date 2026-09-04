import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        background: "#090d16",
        surface: "#0f172a",
        "surface-light": "#1e293b",
        "surface-border": "#334155",
        brand: {
          50: "#eef2ff",
          500: "#6366f1",
          600: "#4f46e5",
          700: "#4338ca",
        },
        threat: {
          safe: "#10b981",
          low: "#3b82f6",
          medium: "#f59e0b",
          high: "#f97316",
          critical: "#ef4444",
        },
      },
      fontFamily: {
        mono: ["Consolas", "Monaco", "'Courier New'", "monospace"],
      },
      boxShadow: {
        glow: "0 0 25px -5px rgba(99, 102, 241, 0.25)",
        "glow-red": "0 0 25px -5px rgba(239, 68, 68, 0.3)",
      },
    },
  },
  plugins: [],
};
export default config;
