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
import { useFindingFilters } from "@/components/report/use-finding-filters";
import { applyFilters } from "@/lib/report/filters";
import { Callout } from "@/components/ui";
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

  return (
    <div className="flex flex-col gap-5">
      <ScanTerminal
        hostname={domain}
        lines={lines}
        running={running}
        cached={cached}
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
        <>
          <div className="grid gap-5 rounded-lg border border-border bg-surface p-4 sm:grid-cols-[auto_1fr] sm:items-center sm:gap-8 sm:p-5">
            <ScoreGauge score={report.score} />
            <div className="min-w-0">
              <ScoreRadar checks={report.checks} />
            </div>
          </div>

          <CoverageNotice score={report.score} checks={report.checks} />

          <section aria-labelledby="findings-heading">
            <h2 id="findings-heading" className="label mb-2 text-fg-subtle">
              Findings
            </h2>

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

          <section aria-labelledby="coverage-heading">
            <h2 id="coverage-heading" className="label mb-2 text-fg-subtle">
              Check coverage
            </h2>
            <CheckCoverage checks={report.checks} />
          </section>

          <p className="font-mono text-2xs text-fg-subtle">
            Scanned {new Date(report.scannedAt).toISOString().replace("T", " ").slice(0, 19)} UTC
            {" · "}
            {report.durationMs}ms
            {cached ? " · served from cache" : ""}
          </p>
        </>
      ) : null}
    </div>
  );
}
