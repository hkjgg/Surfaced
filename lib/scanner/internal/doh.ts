/**
 * DNSSEC lookups over DNS-over-HTTPS.
 *
 * node:dns cannot query DS or DNSKEY — its rrtype list stops at SRV/NAPTR —
 * so delegation-signer records are unreachable through the system resolver.
 * DoH is the passive way to get them: an ordinary HTTPS GET to a public
 * recursive resolver, asking about a third party's public DNS records.
 * Nothing is sent to the scanned domain.
 */

const DOH_ENDPOINTS = [
  "https://cloudflare-dns.com/dns-query",
  "https://dns.google/resolve",
] as const;

/** DNS record type code for DS (RFC 4034). */
const TYPE_DS = 43;

interface DohAnswer {
  readonly name?: string;
  readonly type?: number;
  readonly data?: string;
}

interface DohResponse {
  readonly Status?: number;
  /** Authenticated Data: the resolver validated the DNSSEC chain. */
  readonly AD?: boolean;
  readonly Answer?: readonly DohAnswer[];
}

export interface DnssecResult {
  /** True when the parent zone publishes a DS record for this domain. */
  readonly signed: boolean;
  /** True when the resolver reports it validated the chain (AD flag). */
  readonly authenticatedData: boolean;
  readonly dsRecords: readonly string[];
  /** Which endpoint answered, for the report's provenance. */
  readonly resolver: string;
}

function isDohResponse(value: unknown): value is DohResponse {
  return typeof value === "object" && value !== null;
}

/**
 * Query DS for `name`. Tries each endpoint in turn; throws only when every
 * endpoint fails, so the caller can mark DNSSEC unavailable rather than
 * reporting "unsigned" — which would be a false negative with real
 * consequences.
 */
export async function lookupDnssec(
  name: string,
  signal: AbortSignal,
): Promise<DnssecResult> {
  const failures: string[] = [];

  for (const endpoint of DOH_ENDPOINTS) {
    try {
      const url = new URL(endpoint);
      url.searchParams.set("name", name);
      url.searchParams.set("type", "DS");
      url.searchParams.set("do", "true");

      const response = await fetch(url, {
        signal,
        headers: { accept: "application/dns-json" },
        redirect: "error",
      });

      if (!response.ok) {
        failures.push(`${url.hostname} returned HTTP ${response.status}`);
        continue;
      }

      const body: unknown = await response.json();
      if (!isDohResponse(body)) {
        failures.push(`${url.hostname} returned an unexpected body`);
        continue;
      }

      const dsRecords = (body.Answer ?? [])
        .filter((answer) => answer.type === TYPE_DS)
        .map((answer) => answer.data ?? "")
        .filter((data) => data.length > 0);

      return {
        signed: dsRecords.length > 0,
        authenticatedData: body.AD === true,
        dsRecords,
        resolver: url.hostname,
      };
    } catch (error) {
      failures.push(
        `${new URL(endpoint).hostname}: ${error instanceof Error ? error.message : "failed"}`,
      );
    }
  }

  throw new Error(`No DoH resolver answered (${failures.join("; ")})`);
}
