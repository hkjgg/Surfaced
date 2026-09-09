import { Card, CardBody, CardHeader, CardTitle } from "@/components/ui";
import { cn } from "@/lib/cn";
import type { CheckResult } from "@/lib/scanner/types";
import type { TlsData } from "@/lib/scanner/tls";

/**
 * Narrow a check result's `data` to TlsData.
 *
 * `CheckResult.data` is `unknown` by design, so this is a real shape check
 * rather than a cast. Getting a differently-shaped object here would mean the
 * engine changed, and rendering a timeline from it would produce confident
 * nonsense.
 */
function readTlsData(result: CheckResult | undefined): TlsData | null {
  if (!result || result.status !== "ok" || !result.data) return null;

  const data = result.data as Partial<TlsData>;
  if (typeof data.validFrom !== "string" || typeof data.validTo !== "string") {
    return null;
  }

  return data as TlsData;
}

function formatDate(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;

  return parsed.toISOString().slice(0, 10);
}

interface CertTimelineProps {
  tls: CheckResult | undefined;
}

/**
 * Issued → today → expires.
 *
 * Rendered only when the TLS check returned a certificate. There is no
 * speculative track: if TLS errored, this component renders nothing at all
 * rather than an empty or guessed window.
 */
export function CertTimeline({ tls }: CertTimelineProps) {
  const data = readTlsData(tls);
  if (!data || !data.validFrom || !data.validTo) return null;

  const from = Date.parse(data.validFrom);
  const to = Date.parse(data.validTo);
  if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) return null;

  const now = Date.now();
  const span = to - from;
  const rawProgress = (now - from) / span;

  // Today can legitimately fall outside the validity window — an expired
  // certificate, or one whose start date is in the future. Both are real
  // findings, so the marker is clamped to the track and the state is named in
  // text rather than being silently pinned to an end and looking normal.
  const expired = now > to;
  const notYetValid = now < from;
  const progress = Math.min(1, Math.max(0, rawProgress));

  const days = data.daysUntilExpiry;
  const remaining =
    days === null
      ? null
      : days < 0
        ? `expired ${Math.abs(days)} day${Math.abs(days) === 1 ? "" : "s"} ago`
        : `${days} day${days === 1 ? "" : "s"} left`;

  const tone = expired || notYetValid ? "critical" : days !== null && days <= 30 ? "medium" : "pass";

  return (
    <Card>
      <CardHeader eyebrow="TLS · Validity">
        <CardTitle className="text-base text-fg">Certificate window</CardTitle>
      </CardHeader>

      <CardBody>
        <div className="flex items-baseline justify-between gap-3 font-mono text-2xs tabular-nums text-fg-subtle">
          <span>{formatDate(data.validFrom)}</span>
          <span
            className={cn(
              "label",
              tone === "critical" && "text-critical",
              tone === "medium" && "text-medium",
              tone === "pass" && "text-pass",
            )}
          >
            {expired
              ? "Expired"
              : notYetValid
                ? "Not yet valid"
                : (remaining ?? "Current")}
          </span>
          <span>{formatDate(data.validTo)}</span>
        </div>

        <div
          className="relative mt-2 h-2 rounded-xs bg-raised"
          role="img"
          aria-label={
            expired
              ? `Certificate was valid from ${formatDate(data.validFrom)} to ${formatDate(data.validTo)} and has expired.`
              : notYetValid
                ? `Certificate is not valid until ${formatDate(data.validFrom)}, and expires ${formatDate(data.validTo)}.`
                : `Certificate valid from ${formatDate(data.validFrom)} to ${formatDate(data.validTo)}, ${remaining ?? "currently valid"}.`
          }
        >
          <div
            className={cn(
              "absolute inset-y-0 left-0 rounded-xs",
              tone === "critical" && "bg-critical-wash",
              tone === "medium" && "bg-medium-wash",
              tone === "pass" && "bg-pass-wash",
            )}
            style={{ width: `${progress * 100}%` }}
          />
          <span
            className={cn(
              "absolute top-1/2 h-3.5 w-0.5 -translate-y-1/2 rounded-xs",
              tone === "critical" && "bg-critical",
              tone === "medium" && "bg-medium",
              tone === "pass" && "bg-pass",
            )}
            style={{ left: `calc(${progress * 100}% - 1px)` }}
          />
        </div>

        <div className="mt-1.5 flex items-baseline justify-between gap-3 text-2xs text-fg-subtle">
          <span>Issued</span>
          <span className="text-fg-muted">
            {expired || notYetValid ? "today is outside this window" : "today"}
          </span>
          <span>Expires</span>
        </div>

        {data.issuer ? (
          <p className="mt-3 text-xs text-fg-muted">
            <span className="label text-fg-subtle">Issuer</span>{" "}
            <span data-mono>{data.issuer}</span>
          </p>
        ) : null}
      </CardBody>
    </Card>
  );
}
