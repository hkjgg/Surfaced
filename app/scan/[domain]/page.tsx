import { Suspense } from "react";
import type { Metadata } from "next";
import Link from "next/link";

import { DomainField } from "@/components/domain-field";
import { ReportView } from "@/components/report/report-view";

interface ScanPageProps {
  params: Promise<{ domain: string }>;
}

export async function generateMetadata({
  params,
}: ScanPageProps): Promise<Metadata> {
  const { domain } = await params;
  const hostname = decodeURIComponent(domain);

  return {
    title: `${hostname} — Surfaced`,
    description: `Passive attack-surface report for ${hostname}.`,
  };
}

/**
 * The report page.
 *
 * A thin server shell around a client view: the scan runs over SSE so the log
 * can print each check as it settles, which needs a client. The hostname is
 * passed through as typed — validate.ts on the server is the boundary, and
 * the API route rejects anything it does not like with a message this page
 * renders.
 */
export default async function ScanPage({ params }: ScanPageProps) {
  const { domain } = await params;
  const hostname = decodeURIComponent(domain);

  return (
    <div className="shell py-8 sm:py-12">
      <div className="mb-6 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-2">
        <h1 className="font-mono text-xl tracking-tight text-fg">{hostname}</h1>
        <Link
          href="/"
          className="label text-fg-subtle underline-offset-4 hover:text-fg-muted hover:underline"
        >
          Scan another domain
        </Link>
      </div>

      {/* useSearchParams needs a Suspense boundary; the filter state lives in
          the URL so the report view reads it. */}
      <Suspense
        fallback={
          <div className="min-h-[13.5rem] rounded-lg border border-border bg-surface" />
        }
      >
        <ReportView domain={hostname} />
      </Suspense>

      <div className="mt-10 border-t border-border pt-6">
        <p className="label mb-3 text-fg-subtle">Scan another domain</p>
        <DomainField />
      </div>
    </div>
  );
}
