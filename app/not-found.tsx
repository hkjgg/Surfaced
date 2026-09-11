import type { Metadata } from "next";
import Link from "next/link";

import { DomainField } from "@/components/domain-field";

export const metadata: Metadata = {
  title: "Not found",
};

/**
 * A wrong URL should still lead somewhere useful, so this offers the scanner
 * rather than just an apology and a link back.
 */
export default function NotFound() {
  return (
    <div className="shell flex flex-col py-16 sm:py-24">
      <span className="label text-fg-subtle">Error 404</span>

      <h1 className="mt-2 text-2xl font-medium tracking-tight text-fg">
        No such page
      </h1>

      <p className="mt-3 max-w-md text-base text-fg-muted">
        That route doesn&rsquo;t exist. If you were after a report, the domain
        goes here — a scan is six passive checks against public records.
      </p>

      <div className="mt-8">
        <DomainField showQuickTry />
        <p id="domain-help" className="mt-3 text-xs text-fg-subtle">
          Reports live at <span data-mono>/scan/&lt;domain&gt;</span>.
        </p>
      </div>

      <Link
        href="/"
        className="mt-10 w-fit rounded-xs text-sm text-accent underline underline-offset-4 hover:text-fg"
      >
        Back to the scanner
      </Link>
    </div>
  );
}
