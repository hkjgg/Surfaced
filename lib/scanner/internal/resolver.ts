/**
 * DNS access for every check.
 *
 * Wraps node:dns/promises so callers get a bounded wall time and a small,
 * typed error vocabulary instead of raw libc error codes. Absence of a record
 * (NODATA/NXDOMAIN) is a normal, expected answer here — it is returned as an
 * empty array, not thrown — because "this domain publishes no SPF record" is
 * a finding, not a failure.
 */

import { Resolver } from "node:dns/promises";

import { withTimeout } from "./timeout";

/** Error codes that mean "the name or record simply isn't there". */
const ABSENT_CODES = new Set(["ENOTFOUND", "ENODATA", "NXDOMAIN"]);

const DEFAULT_QUERY_TIMEOUT_MS = 5_000;

export interface MxRecord {
  readonly exchange: string;
  readonly priority: number;
}

export interface SoaRecord {
  readonly nsname: string;
  readonly hostmaster: string;
  readonly serial: number;
}

function isAbsent(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    typeof error.code === "string" &&
    ABSENT_CODES.has(error.code)
  );
}

function newResolver(): Resolver {
  // Node's Resolver carries its own timeout/retry budget. Keeping it short
  // matters because a truncated UDP answer that needs TCP fallback can
  // otherwise hang for the better part of a minute.
  return new Resolver({ timeout: 3_000, tries: 2 });
}

async function query<T>(
  label: string,
  timeoutMs: number,
  run: (resolver: Resolver) => Promise<T[]>,
): Promise<T[]> {
  const resolver = newResolver();
  try {
    return await withTimeout(run(resolver), timeoutMs, label);
  } catch (error) {
    if (isAbsent(error)) return [];
    throw error;
  } finally {
    resolver.cancel();
  }
}

/**
 * TXT records, with each record's character-strings joined.
 *
 * DNS splits strings longer than 255 bytes into chunks; a long SPF or DKIM
 * record arrives as several fragments of one record and must be concatenated
 * with no separator before parsing.
 */
export async function resolveTxt(
  name: string,
  timeoutMs = DEFAULT_QUERY_TIMEOUT_MS,
): Promise<string[]> {
  const records = await query(`TXT ${name}`, timeoutMs, (r) => r.resolveTxt(name));
  return records.map((chunks) => chunks.join(""));
}

export async function resolveMx(
  name: string,
  timeoutMs = DEFAULT_QUERY_TIMEOUT_MS,
): Promise<MxRecord[]> {
  return query(`MX ${name}`, timeoutMs, (r) => r.resolveMx(name));
}

export async function resolveNs(
  name: string,
  timeoutMs = DEFAULT_QUERY_TIMEOUT_MS,
): Promise<string[]> {
  return query(`NS ${name}`, timeoutMs, (r) => r.resolveNs(name));
}

export async function resolveSoa(
  name: string,
  timeoutMs = DEFAULT_QUERY_TIMEOUT_MS,
): Promise<SoaRecord | null> {
  const resolver = newResolver();
  try {
    return await withTimeout(resolver.resolveSoa(name), timeoutMs, `SOA ${name}`);
  } catch (error) {
    if (isAbsent(error)) return null;
    throw error;
  } finally {
    resolver.cancel();
  }
}

/** True when the name exists in DNS at all (any A/AAAA/MX/TXT/CNAME answer). */
export async function resolveAddresses(
  name: string,
  signal?: AbortSignal,
  timeoutMs = DEFAULT_QUERY_TIMEOUT_MS,
): Promise<string[]> {
  signal?.throwIfAborted();

  const resolver = newResolver();
  const onAbort = () => resolver.cancel();
  signal?.addEventListener("abort", onAbort, { once: true });

  try {
    const [v4, v6] = await Promise.all([
      withTimeout(resolver.resolve4(name), timeoutMs, `A ${name}`).catch(
        (error: unknown) => {
          if (isAbsent(error)) return [] as string[];
          throw error;
        },
      ),
      withTimeout(resolver.resolve6(name), timeoutMs, `AAAA ${name}`).catch(
        (error: unknown) => {
          if (isAbsent(error)) return [] as string[];
          throw error;
        },
      ),
    ]);
    return [...v4, ...v6];
  } finally {
    signal?.removeEventListener("abort", onAbort);
    resolver.cancel();
  }
}
