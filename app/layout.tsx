import type { Metadata, Viewport } from "next";
import { GeistMono } from "geist/font/mono";
import { GeistSans } from "geist/font/sans";

import { SiteFooter } from "@/components/layout/site-footer";
import { getSiteUrl } from "@/lib/site-url";
import { SiteHeader } from "@/components/layout/site-header";

import "./globals.css";

const DESCRIPTION =
  "Enter a domain. Surfaced reads publicly available DNS, HTTP header, TLS and Certificate Transparency data, then returns a scored report with prioritised findings. Every scan is passive and read-only.";

/**
 * `metadataBase` now comes from lib/site-url.ts.
 *
 * Open Graph needs absolute URLs, so the app has to know its own origin — the
 * one thing it can only learn from the environment. That module validates the
 * value the way CLAUDE.md §4 requires and returns null when it is absent, in
 * which case this is simply left unset and the build still succeeds with no
 * variables at all.
 */
export function generateMetadata(): Metadata {
  const siteUrl = getSiteUrl();

  return {
    ...(siteUrl ? { metadataBase: siteUrl } : {}),
    title: {
      // Routes set only their own name; this appends the product.
      template: "%s — Surfaced",
      default: "Surfaced — passive attack surface scanner",
    },
    description: DESCRIPTION,
    applicationName: "Surfaced",
    openGraph: {
      type: "website",
      siteName: "Surfaced",
      title: "Surfaced — passive attack surface scanner",
      description: DESCRIPTION,
    },
    twitter: {
      card: "summary_large_image",
      title: "Surfaced — passive attack surface scanner",
      description: DESCRIPTION,
    },
  };
}

export const viewport: Viewport = {
  themeColor: "#0a0b0d",
  colorScheme: "dark",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${GeistSans.variable} ${GeistMono.variable}`}>
      <body className="flex min-h-dvh flex-col">
        <a
          href="#main"
          className="sr-only rounded-md bg-accent px-3 py-2 text-sm font-medium text-fg-invert focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50"
        >
          Skip to content
        </a>

        <SiteHeader />
        <main id="main" className="flex-1">
          {children}
        </main>
        <SiteFooter />
      </body>
    </html>
  );
}
