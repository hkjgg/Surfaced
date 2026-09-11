import type { Metadata } from "next";

import { DomainField } from "@/components/domain-field";
import { TelemetryStrip } from "@/components/telemetry-strip";
import { Wordmark } from "@/components/layout/wordmark";

export const metadata: Metadata = {
  // `absolute` opts out of the layout's "%s — Surfaced" template, which would
  // otherwise render "Surfaced — passive attack surface scanner — Surfaced".
  title: { absolute: "Surfaced — passive attack surface scanner" },
};

export default function HomePage() {
  return (
    <div className="relative isolate">
      {/* Ground texture: a plotting-surface dot grid that fades out before it
          reaches the content. Pure CSS, static, no image — see the dot-matrix
          utility in globals.css. */}
      <div
        aria-hidden="true"
        className="dot-matrix pointer-events-none absolute inset-x-0 top-0 -z-10 h-[28rem]"
      />

      <div className="shell flex flex-col justify-center py-16 sm:py-24">
        <Wordmark size="lg" />

        <p className="mt-4 max-w-xl text-base text-fg-muted">
          See what your domain reveals to anyone who looks — DNS, headers,
          certificates — scored and ranked, without touching your systems.
        </p>

        <p className="mt-3 max-w-xl text-sm text-fg-subtle">
          Six passive checks against public records. Nothing is sent to your
          servers.
        </p>

        <div className="relative mt-8">
          {/* A hint of accent behind the field, same painted gradient as the
              score card's ambient tint. Static. */}
          <div
            aria-hidden="true"
            /* -inset-x-4 (16px) stays inside the 20px shell gutter; -inset-x-6
               pushed 4px past the viewport at 375 and scrolled the page. */
            className="score-glow pointer-events-none absolute -inset-x-4 -inset-y-10 -z-10 text-accent"
          />

          <DomainField showQuickTry />

          <p id="domain-help" className="mt-3 text-xs text-fg-subtle">
            Enter any domain. Surfaced reads public DNS, TLS and Certificate
            Transparency records, and makes one ordinary HTTPS request for
            response headers.
          </p>
        </div>

        <div className="mt-10 border-t border-border pt-4">
          <TelemetryStrip />
        </div>
      </div>
    </div>
  );
}
