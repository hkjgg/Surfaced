"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";

import { CertTimeline } from "@/components/report/cert-timeline";
import { CheckCoverage } from "@/components/report/check-coverage";
import { CoverageNotice } from "@/components/report/coverage-notice";
import { FilterBar } from "@/components/report/filter-bar";
import { FindingCard } from "@/components/report/finding-card";
import { ScanTerminal, type TerminalLine } from "@/components/report/scan-terminal";
import { ScoreGauge } from "@/components/report/score-gauge";
import { ScoreRadar } from "@/components/report/score-radar";
import { SectionHeading } from "@/components/report/section-heading";
import { TONE_TEXT } from "@/components/report/tone";
import { useFindingFilters } from "@/components/report/use-finding-filters";
import { applyFilters } from "@/lib/report/filters";
import { Callout } from "@/components/ui";
import { cn } from "@/lib/cn";
import { scoreBand } from "@/lib/scanner/score";
import type { ScanReport } from "@/lib/scanner/types";

interface ScanError {
  readonly code: string;
  readonly message: string;
}

interface ReportViewProps {
  domain: string;
}

/**
 * Reads the SSE stream and assembles the report as it arrives.
 *
 * The terminal is populated from real `check` events, so the log reflects the
 * order checks actually settled in — which is rarely the order they are listed
 * in, and is worth seeing.
 */
export function ReportView({ domain }: ReportViewProps) {
  const [lines, setLines] = useState<TerminalLine[]>([]);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<ScanError | null>(null);
  const [cached, setCached] = useState(false);
  const [running, setRunning] = useState(true);

  const filters = useFindingFilters();
  // React 18 StrictMode mounts effects twice in development; without this the
  // scan would run twice and consume two of the ten hourly slots.
  const startedRef = useRef(false);

  useEffect(() => {
    if (startedRef.current) return;
    startedRef.current = true;

    const controller = new AbortController();

    async function run() {
      try {
        const response = await fetch("/api/scan", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            accept: "text/event-stream",
          },
          body: JSON.stringify({ domain }),
          signal: controller.signal,
        });

        if (!response.ok || !response.body) {
          const body = (await response.json().catch(() => null)) as
            | { error?: ScanError }
            | null;

          setError(
            body?.error ?? {
              code: "unexpected",
              message: `The scanner returned HTTP ${response.status}.`,
            },
          );
          setRunning(false);
          return;
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });

          let boundary = buffer.indexOf("\n\n");
          while (boundary !== -1) {
            const frame = buffer.slice(0, boundary);
            buffer = buffer.slice(boundary + 2);
            handleFrame(frame);
            boundary = buffer.indexOf("\n\n");
          }
        }

        setRunning(false);
      } catch (cause) {
        if (controller.signal.aborted) return;

        setError({
          code: "network",
          message:
            cause instanceof Error
              ? `The connection to the scanner failed: ${cause.message}`
              : "The connection to the scanner failed.",
        });
        setRunning(false);
      }
    }

    function handleFrame(frame: string) {
      const name = /^event: (.+)$/m.exec(frame)?.[1];
      const payload = /^data: (.+)$/m.exec(frame)?.[1];
      if (!name || !payload) return;

      const data: unknown = JSON.parse(payload);

      if (name === "start") {
        const start = data as { cached?: boolean };
        setCached(start.cached === true);
        return;
      }

      if (name === "check") {
        setLines((current) => [...current, data as TerminalLine]);
        return;
      }

      if (name === "report") {
        setReport((data as { report: ScanReport }).report);
        setRunning(false);
        return;
      }

      if (name === "error") {
        setError(data as ScanError);
        setRunning(false);
      }
    }

    void run();
    return () => controller.abort();
  }, [domain]);

  const visible = report ? applyFilters(report.findings, filters) : [];
  const band =
    report && report.score.value !== null ? scoreBand(report.score.value) : null;

  return (
    <div className="flex flex-col gap-5">
      <ScanTerminal
        hostname={domain}
        lines={lines}
        running={running}
        cached={cached}
        durationMs={report?.durationMs}
      />

      {error ? (
        <Callout tone="critical" title={`Scan failed · ${error.code}`}>
          <p>{error.message}</p>
          <p className="mt-2">
            <Link
              href="/"
              className="text-accent underline underline-offset-2"
            >
              Scan a different domain
            </Link>
          </p>
        </Callout>
      ) : null}

      {report ? (
        /* Two columns from 1024px: the verdict stays put while the evidence
           scrolls past it. One column below that, in the same order. */
        <div className="lg:grid lg:grid-cols-[minmax(0,21rem)_minmax(0,1fr)] lg:items-start lg:gap-6">
          {/* `self-start` is load-bearing: a grid item stretches to the row
             height by default, and a stretched item can never stick. The
             max-height matters too — a sticky element taller than the viewport
             silently stops sticking, and this column runs tall on a short
             laptop screen. */}
          {/* `shrink-0` on every child is load-bearing alongside the max-height:
             flex children default to shrink:1, so a column that overflows its
             max-height compresses them instead of scrolling — which crushed the
             score card to a sliver and clipped the coverage cells. */}
          <div className="flex flex-col gap-4 lg:sticky lg:top-sticky lg:max-h-[calc(100dvh-var(--spacing-sticky)-1rem)] lg:self-start lg:overflow-y-auto lg:pr-1 lg:[&>*]:shrink-0">
            <div className="relative isolate overflow-hidden rounded-lg border border-border bg-surface p-4 sm:p-5">
              {/* Ambient tint, hue supplied by the band via currentColor. It
                  is painted, not animated — nothing to gate. */}
              {band ? (
                <div
                  aria-hidden="true"
                  className={cn(
                    "score-glow pointer-events-none absolute -inset-x-8 -top-16 -z-10 h-72",
                    TONE_TEXT[band],
                  )}
                />
              ) : null}

              <ScoreGauge score={report.score} />

              <div className="mt-5 min-w-0 border-t border-border pt-4">
                <ScoreRadar checks={report.checks} />
              </div>
            </div>

            <CoverageNotice score={report.score} checks={report.checks} />

            <section aria-labelledby="coverage-heading">
              <SectionHeading
                id="coverage-heading"
                meta={`${report.score.checksIncluded.length}/${report.checks.length}`}
              >
                Check coverage
              </SectionHeading>
              <CheckCoverage checks={report.checks} />
            </section>
          </div>

          <div className="mt-5 flex flex-col gap-5 lg:mt-0">
            <section aria-labelledby="findings-heading">
              <SectionHeading
                id="findings-heading"
                meta={
                  visible.length === report.findings.length
                    ? `${report.findings.length}`
                    : `${visible.length} of ${report.findings.length}`
                }
              >
                Findings
              </SectionHeading>

              <FilterBar
                findings={report.findings}
                visibleCount={visible.length}
                filters={filters}
              />

              {visible.length === 0 ? (
                <p className="mt-3 rounded-lg border border-border bg-surface px-4 py-6 text-center text-sm text-fg-muted">
                  No findings match the current filters.
                </p>
              ) : (
                <ul className="mt-3 flex flex-col gap-2">
                  {visible.map((finding, index) => (
                    <FindingCard
                      key={finding.id}
                      finding={finding}
                      index={index}
                    />
                  ))}
                </ul>
              )}
            </section>

            <CertTimeline
              tls={report.checks.find((check) => check.check === "tls")}
            />

            <p className="font-mono text-2xs text-fg-subtle">
              Scanned {new Date(report.scannedAt).toISOString().replace("T", " ").slice(0, 19)} UTC
              {" · "}
              {report.durationMs}ms
              {cached ? " · served from cache" : ""}
            </p>
          </div>
        </div>
      ) : null}
    </div>
  );
}
