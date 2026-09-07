import Link from "next/link";

import { Wordmark } from "./wordmark";

export function SiteHeader() {
  return (
    <header className="sticky top-0 z-10 border-b border-border bg-bg/85 backdrop-blur-sm">
      <div className="shell flex h-14 items-center justify-between gap-3">
        <Link href="/" className="rounded-xs" aria-label="Surfaced, home">
          <Wordmark />
        </Link>

        {/* Says what the tool does, in the tool's own register. */}
        <span className="label text-fg-subtle">Passive recon</span>
      </div>
    </header>
  );
}
