import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "OnionSec Security Dashboard",
  description: "Modern cybersecurity scanner and correlation dashboard for Tor hidden services",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
