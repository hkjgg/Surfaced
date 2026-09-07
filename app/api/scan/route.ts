/**
 * POST /api/scan
 *
 * The scanner's only public surface. Validates input, runs the six passive
 * checks, and returns the typed report.
 */

import { NextResponse } from "next/server";

import { scanHostname } from "@/lib/scanner/orchestrate";
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

export async function POST(request: Request): Promise<NextResponse> {
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

  const cached = readCache(hostname, now);
  if (cached) {
    return NextResponse.json(cached, {
      headers: {
        "x-cache": "hit",
        "x-ratelimit-limit": String(RATE_LIMIT_MAX),
        "x-ratelimit-remaining": String(limit.remaining),
      },
    });
  }

  const report = await scanHostname(hostname, { signal: request.signal });
  writeCache(hostname, report, now);

  // 200 even when some checks failed: the report carries per-check status and
  // marks the score partial, which is more useful than an opaque 5xx.
  return NextResponse.json(report, {
    headers: {
      "x-cache": "miss",
      "x-ratelimit-limit": String(RATE_LIMIT_MAX),
      "x-ratelimit-remaining": String(limit.remaining),
    },
  });
}
