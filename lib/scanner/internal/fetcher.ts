/**
 * Redirect-following fetch that re-checks the SSRF boundary on every hop.
 *
 * Using `redirect: "follow"` would hand redirect handling to undici, which
 * would happily follow a 302 from a public site to http://169.254.169.254/.
 * Validation at the entry point only covers the hostname the user typed, so
 * redirects are followed manually and each new location is validated as if it
 * had been typed fresh.
 */

import { validateDomain } from "../validate";

export interface FetchHop {
  readonly url: string;
  readonly status: number;
  readonly location: string | null;
}

export interface SafeFetchResult {
  readonly response: Response;
  /** Every hop taken, in order, including the final one. */
  readonly hops: readonly FetchHop[];
  /** The URL that produced the final response. */
  readonly finalUrl: string;
}

export class RedirectBlockedError extends Error {
  constructor(
    readonly target: string,
    reason: string,
  ) {
    super(`Refused to follow redirect to ${target}: ${reason}`);
    this.name = "RedirectBlockedError";
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * A browser-shaped identity. Surfaced identifies itself honestly rather than
 * spoofing a browser UA — evading filtering would breach the passive-only
 * rule in CLAUDE.md just as much as an active probe would.
 */
export const USER_AGENT =
  "Surfaced/1.0 (+https://github.com/hkjgg/Surfaced; passive security header scanner)";

export async function safeFetch(
  initialUrl: string,
  options: {
    readonly method: "HEAD" | "GET";
    readonly signal: AbortSignal;
    readonly maxRedirects?: number;
  },
): Promise<SafeFetchResult> {
  const maxRedirects = options.maxRedirects ?? 5;
  const hops: FetchHop[] = [];

  let currentUrl = initialUrl;

  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    const response = await fetch(currentUrl, {
      method: options.method,
      redirect: "manual",
      signal: options.signal,
      headers: {
        "user-agent": USER_AGENT,
        accept: "*/*",
      },
    });

    const location = response.headers.get("location");
    hops.push({ url: currentUrl, status: response.status, location });

    if (!REDIRECT_STATUSES.has(response.status) || !location) {
      return { response, hops, finalUrl: currentUrl };
    }

    // Resolve relative Locations against the current URL, as a browser would.
    let nextUrl: URL;
    try {
      nextUrl = new URL(location, currentUrl);
    } catch {
      throw new RedirectBlockedError(location, "the Location header is not a valid URL");
    }

    if (nextUrl.protocol !== "https:" && nextUrl.protocol !== "http:") {
      throw new RedirectBlockedError(nextUrl.href, "non-HTTP scheme");
    }

    // The whole point of this function: every hop is a fresh SSRF decision.
    const verdict = await validateDomain(nextUrl.hostname, options.signal);
    if (!verdict.ok) {
      throw new RedirectBlockedError(nextUrl.href, verdict.message);
    }

    // Drain the body so the socket can be reused rather than left dangling.
    await response.body?.cancel();

    currentUrl = nextUrl.href;
  }

  throw new Error(`Exceeded ${maxRedirects} redirects`);
}
