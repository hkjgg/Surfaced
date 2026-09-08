/**
 * POST /api/scan
 *
 * The scanner's only public surface. Validates input, runs the six passive
 * checks, and returns the typed report.
 *
 * Two response shapes, chosen by content negotiation:
 *
 *   - `Accept: text/event-stream` → Server-Sent Events, one `check` event as
 *     each check settles, then a final `report` event.
 *   - anything else → the single JSON report, unchanged.
 *
 * The JSON form is the original contract and stays byte-identical, so existing
 * callers — including scripts/verify-scanner.mjs — keep working. Streaming is
 * additive.
 */

import { NextResponse } from "next/server";

import {
  replayEvents,
  scanHostnameStream,
  type ScanEvent,
} from "@/lib/scanner/orchestrate";
import type { ScanReport } from "@/lib/scanner/types";
import { validateDomain } from "@/lib/scanner/validate";

// node:dns and node:tls do not exist on the Edge runtime, so this route must
// run on Node. Without this the build succeeds and every scan fails at runtime.
export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;
const CACHE_TTL_MS = 60 * 1000;

/**
 * In-memory rate limiting and caching.
 *
 * Honest limitation: this is per-instance state. On Vercel, concurrent lambdas
 * each hold their own Map, so the effective limit is (instances × 10) per hour
 * and the cache hit rate falls with fan-out. It is a courtesy control that
 * stops one client hammering one instance — not a quota, and not a defence
 * against a determined caller. A real limit needs shared storage; that is what
 * the (currently unused) Supabase client is eventually for.
 */
const rateLimitBuckets = new Map<string, number[]>();
const reportCache = new Map<string, { report: ScanReport; expiresAt: number }>();

/** Bound memory growth on a long-lived instance. */
const MAX_TRACKED_CLIENTS = 10_000;
const MAX_CACHED_REPORTS = 500;

interface RateLimitVerdict {
  readonly allowed: boolean;
  readonly remaining: number;
  readonly retryAfterSeconds: number;
}

function clientKey(request: Request): string {
  // Vercel sets x-forwarded-for; the leftmost entry is the client. This is
  // spoofable in general, which is another reason the limit is a courtesy
  // control rather than a security boundary.
  const forwarded = request.headers.get("x-forwarded-for");
  const first = forwarded?.split(",")[0]?.trim();
  return first && first.length > 0 ? first : "unknown";
}

function checkRateLimit(key: string, now: number): RateLimitVerdict {
  const windowStart = now - RATE_LIMIT_WINDOW_MS;
  const recent = (rateLimitBuckets.get(key) ?? []).filter(
    (timestamp) => timestamp > windowStart,
  );

  if (recent.length >= RATE_LIMIT_MAX) {
    const oldest = recent[0] ?? now;
    return {
      allowed: false,
      remaining: 0,
      retryAfterSeconds: Math.max(
        1,
        Math.ceil((oldest + RATE_LIMIT_WINDOW_MS - now) / 1000),
      ),
    };
  }

  recent.push(now);
  rateLimitBuckets.set(key, recent);

  if (rateLimitBuckets.size > MAX_TRACKED_CLIENTS) {
    for (const [candidate, stamps] of rateLimitBuckets) {
      if (stamps.every((timestamp) => timestamp <= windowStart)) {
        rateLimitBuckets.delete(candidate);
      }
    }
  }

  return {
    allowed: true,
    remaining: RATE_LIMIT_MAX - recent.length,
    retryAfterSeconds: 0,
  };
}

function readCache(hostname: string, now: number): ScanReport | null {
  const entry = reportCache.get(hostname);
  if (!entry) return null;

  if (entry.expiresAt <= now) {
    reportCache.delete(hostname);
    return null;
  }

  return entry.report;
}

function writeCache(hostname: string, report: ScanReport, now: number): void {
  if (reportCache.size >= MAX_CACHED_REPORTS) {
    for (const [key, entry] of reportCache) {
      if (entry.expiresAt <= now) reportCache.delete(key);
    }
    // Still full of live entries: drop the oldest insertion.
    if (reportCache.size >= MAX_CACHED_REPORTS) {
      const oldest = reportCache.keys().next();
      if (!oldest.done) reportCache.delete(oldest.value);
    }
  }

  reportCache.set(hostname, { report, expiresAt: now + CACHE_TTL_MS });
}

function errorResponse(
  status: number,
  code: string,
  message: string,
  headers?: HeadersInit,
): NextResponse {
  return NextResponse.json({ error: { code, message } }, { status, headers });
}

function wantsEventStream(request: Request): boolean {
  return (request.headers.get("accept") ?? "").includes("text/event-stream");
}

/**
 * Wrap an event source in an SSE response.
 *
 * Errors are reported as a final `error` event rather than a dropped
 * connection, so a client can tell "the scan failed" apart from "the network
 * died" — which are different things and want different messages.
 */
function eventStreamResponse(
  events: () => AsyncIterable<ScanEvent>,
  extraHeaders: Record<string, string>,
): Response {
  const encoder = new TextEncoder();

  const stream = new ReadableStream<Uint8Array>({
    async start(controller) {
      const send = (name: string, payload: unknown) => {
        controller.enqueue(
          encoder.encode(`event: ${name}\ndata: ${JSON.stringify(payload)}\n\n`),
        );
      };

      try {
        for await (const event of events()) {
          send(event.type, event);
        }
      } catch (error) {
        send("error", {
          code: "scan_failed",
          message:
            error instanceof Error ? error.message : "The scan failed unexpectedly.",
        });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      // no-transform matters as much as no-store: a compressing proxy will
      // happily buffer the whole stream, which turns per-check events back
      // into one delivery at the end.
      "cache-control": "no-store, no-transform",
      "x-accel-buffering": "no",
      ...extraHeaders,
    },
  });
}

export async function POST(request: Request): Promise<Response> {
  const now = Date.now();

  const limit = checkRateLimit(clientKey(request), now);
  if (!limit.allowed) {
    return errorResponse(
      429,
      "rate_limited",
      `Rate limit reached. Up to ${RATE_LIMIT_MAX} scans are allowed per hour.`,
      {
        "retry-after": String(limit.retryAfterSeconds),
        "x-ratelimit-limit": String(RATE_LIMIT_MAX),
        "x-ratelimit-remaining": "0",
      },
    );
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse(400, "invalid_body", "Request body must be JSON.");
  }

  const domain =
    typeof body === "object" && body !== null && "domain" in body
      ? (body as { domain: unknown }).domain
      : undefined;

  if (typeof domain !== "string") {
    return errorResponse(400, "invalid_body", 'Provide a "domain" string.');
  }

  const validation = await validateDomain(domain, request.signal);
  if (!validation.ok) {
    return errorResponse(400, validation.code, validation.message);
  }

  const { hostname } = validation;

  const streaming = wantsEventStream(request);
  const cached = readCache(hostname, now);

  if (cached) {
    const headers = {
      "x-cache": "hit",
      "x-ratelimit-limit": String(RATE_LIMIT_MAX),
      "x-ratelimit-remaining": String(limit.remaining),
    };

    if (!streaming) return NextResponse.json(cached, { headers });

    // Replay the events the cached scan produced. The start event carries
    // cached: true so the client says so instead of implying it just measured
    // these timings.
    return eventStreamResponse(async function* () {
      yield* replayEvents(cached);
    }, headers);
  }

  const headers = {
    "x-cache": "miss",
    "x-ratelimit-limit": String(RATE_LIMIT_MAX),
    "x-ratelimit-remaining": String(limit.remaining),
  };

  if (streaming) {
    return eventStreamResponse(async function* () {
      for await (const event of scanHostnameStream(hostname, {
        signal: request.signal,
      })) {
        if (event.type === "report") writeCache(hostname, event.report, Date.now());
        yield event;
      }
    }, headers);
  }

  let report: ScanReport | null = null;
  for await (const event of scanHostnameStream(hostname, { signal: request.signal })) {
    if (event.type === "report") report = event.report;
  }

  if (!report) {
    return errorResponse(500, "scan_failed", "The scan produced no report.");
  }

  writeCache(hostname, report, now);

  // 200 even when some checks failed: the report carries per-check status and
  // marks the score partial, which is more useful than an opaque 5xx.
  return NextResponse.json(report, { headers });
}
