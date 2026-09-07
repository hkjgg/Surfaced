/**
 * Breach signal.
 *
 * This check exists to answer "has mail for this domain shown up in a known
 * breach?" — and, far more often, to say clearly that it cannot answer.
 *
 * Have I Been Pwned's domain search only returns data for domains the API key
 * holder has verified they control. A public scanner scanning a stranger's
 * domain therefore cannot get a real answer, and the honest output is
 * `not_configured`. That state is excluded from scoring rather than counted
 * as a pass, because "we didn't look" and "we looked and it was clean" are
 * different facts and must never be shown as the same one.
 *
 * Under no circumstances does this module synthesise breach data.
 */

import type { CheckResult, Finding } from "./types";

const CHECK = "exposure" as const;

const HIBP_ENDPOINT = "https://haveibeenpwned.com/api/v3/breacheddomain/";
const REQUEST_TIMEOUT_MS = 8_000;

export interface ExposureData {
  readonly source: "hibp";
  /** Breach names, only ever populated from a real API response. */
  readonly breaches: readonly string[];
  readonly affectedAccounts: number | null;
}

interface HibpResponse {
  /** Map of local part -> breach names. */
  readonly [alias: string]: readonly string[];
}

function readApiKey(): string | null {
  const key = process.env.HIBP_API_KEY?.trim();
  return key && key.length > 0 ? key : null;
}

export async function checkExposure(
  hostname: string,
  signal: AbortSignal,
): Promise<CheckResult<ExposureData>> {
  const started = Date.now();
  signal.throwIfAborted();

  const apiKey = readApiKey();

  if (!apiKey) {
    return {
      check: CHECK,
      status: "not_configured",
      reason:
        "No Have I Been Pwned API key is configured, so breach exposure was not checked. This is not a statement that the domain is clean — it means the question was not asked. HIBP's domain search also only returns data for domains the key holder has verified they control.",
      findings: [],
      durationMs: Date.now() - started,
    };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const onParentAbort = () => controller.abort();
  signal.addEventListener("abort", onParentAbort, { once: true });

  try {
    // The hostname reached here has already passed validate.ts, and is
    // appended as a single encoded path segment rather than interpolated.
    const url = new URL(encodeURIComponent(hostname), HIBP_ENDPOINT);

    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        "hibp-api-key": apiKey,
        "user-agent": "Surfaced/1.0",
        accept: "application/json",
      },
      redirect: "error",
    });

    // 404 is HIBP's "no breached accounts for this domain" answer.
    if (response.status === 404) {
      return {
        check: CHECK,
        status: "ok",
        findings: [
          {
            id: "exposure.none",
            check: CHECK,
            severity: "pass",
            title: "No breached accounts reported for this domain",
            observed: `Have I Been Pwned reports no breached accounts for ${hostname}.`,
            impact: "No addresses at this domain appear in the breaches HIBP tracks.",
          },
        ],
        data: { source: "hibp", breaches: [], affectedAccounts: 0 },
        durationMs: Date.now() - started,
      };
    }

    if (response.status === 401 || response.status === 403) {
      return {
        check: CHECK,
        status: "not_configured",
        reason:
          "Have I Been Pwned rejected the API key, or this domain is not verified as belonging to the key holder. Breach exposure was not checked.",
        findings: [],
        durationMs: Date.now() - started,
      };
    }

    if (!response.ok) {
      throw new Error(`Have I Been Pwned returned HTTP ${response.status}`);
    }

    const body = (await response.json()) as HibpResponse;

    const breaches = new Set<string>();
    let affectedAccounts = 0;

    for (const names of Object.values(body)) {
      affectedAccounts += 1;
      for (const name of names) breaches.add(name);
    }

    const findings: Finding[] = [];

    if (breaches.size > 0) {
      findings.push({
        id: "exposure.breached-accounts",
        check: CHECK,
        severity: "medium",
        title: `${affectedAccounts} address${affectedAccounts === 1 ? "" : "es"} at this domain appear in known breaches`,
        observed: `Have I Been Pwned lists ${affectedAccounts} affected address${
          affectedAccounts === 1 ? "" : "es"
        } across ${breaches.size} breach${breaches.size === 1 ? "" : "es"}: ${[...breaches].sort().join(", ")}.`,
        impact:
          "Credentials from these breaches are reused. Any account whose password was reused elsewhere is reachable by anyone with the breach data.",
        remediation: {
          summary:
            "Force a password reset for the affected accounts and require multi-factor authentication.",
          reference: "https://haveibeenpwned.com/",
        },
      });
    } else {
      findings.push({
        id: "exposure.none",
        check: CHECK,
        severity: "pass",
        title: "No breached accounts reported for this domain",
        observed: `Have I Been Pwned reports no breached accounts for ${hostname}.`,
        impact: "No addresses at this domain appear in the breaches HIBP tracks.",
      });
    }

    return {
      check: CHECK,
      status: "ok",
      findings,
      data: {
        source: "hibp",
        breaches: [...breaches].sort(),
        affectedAccounts,
      },
      durationMs: Date.now() - started,
    };
  } finally {
    clearTimeout(timer);
    signal.removeEventListener("abort", onParentAbort);
  }
}
