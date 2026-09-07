/**
 * HTTP response security headers.
 *
 * One ordinary request to the site's front door, exactly as a browser makes
 * when someone visits. HEAD first because it is the cheapest thing that
 * returns headers; GET only if the server rejects HEAD, which some do.
 */

import type { CheckResult, Finding } from "./types";
import { RedirectBlockedError, safeFetch, type FetchHop } from "./internal/fetcher";

const CHECK = "headers" as const;

/**
 * Six months, the minimum for hstspreload.org submission and the usual
 * recommended floor. Shorter max-age values leave a wider window in which a
 * first visit over http can be intercepted.
 */
const HSTS_MIN_MAX_AGE = 15_768_000;

export interface HeadersData {
  readonly finalUrl: string;
  readonly status: number;
  readonly method: "HEAD" | "GET";
  readonly hops: readonly FetchHop[];
  /** Every response header, lowercased. */
  readonly headers: Readonly<Record<string, string>>;
  /** null when the http:// probe itself failed. */
  readonly httpRedirectsToHttps: boolean | null;
  readonly httpRedirectNote: string | null;
}

function parseHsts(value: string): {
  maxAge: number | null;
  includeSubDomains: boolean;
  preload: boolean;
} {
  const maxAgeMatch = value.match(/max-age\s*=\s*"?(\d+)"?/i);
  const parsed = maxAgeMatch?.[1] ? Number.parseInt(maxAgeMatch[1], 10) : Number.NaN;

  return {
    maxAge: Number.isFinite(parsed) ? parsed : null,
    includeSubDomains: /includeSubDomains/i.test(value),
    preload: /preload/i.test(value),
  };
}

/** Only flag Server/X-Powered-By when they actually disclose a version. */
function leaksVersion(value: string): boolean {
  return /\d+\.\d+/.test(value) || /\/\d/.test(value);
}

function collectHeaders(response: Response): Record<string, string> {
  const out: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

/**
 * Does http:// redirect to https://?
 *
 * Separate from the main request and deliberately non-fatal: plenty of
 * hardened sites refuse plain http entirely, which is not a failure.
 */
async function checkHttpRedirect(
  hostname: string,
  signal: AbortSignal,
): Promise<{ redirects: boolean | null; note: string | null }> {
  try {
    const result = await safeFetch(`http://${hostname}/`, {
      method: "HEAD",
      signal,
      maxRedirects: 3,
    });
    await result.response.body?.cancel();

    const reachedHttps = result.finalUrl.startsWith("https://");
    const redirectedAtFirstHop = (result.hops[0]?.location ?? "").startsWith("https://");

    return {
      redirects: reachedHttps || redirectedAtFirstHop,
      note: null,
    };
  } catch (error) {
    // Distinguish "we could not reach it" from "we reached it and refused to
    // follow where it pointed". Reporting the second as the first would be a
    // small lie about what the scanner actually observed.
    if (error instanceof RedirectBlockedError) {
      return {
        redirects: null,
        note: `http://${hostname}/ redirected somewhere the scanner will not follow: ${error.message}`,
      };
    }

    return {
      redirects: null,
      note: `The http:// endpoint could not be reached (${
        error instanceof Error ? error.message : "unknown error"
      }). Refusing plain HTTP entirely is also a valid posture.`,
    };
  }
}

export async function checkHeaders(
  hostname: string,
  signal: AbortSignal,
): Promise<CheckResult<HeadersData>> {
  const started = Date.now();
  signal.throwIfAborted();

  const origin = `https://${hostname}/`;

  let method: "HEAD" | "GET" = "HEAD";
  let result = await safeFetch(origin, { method, signal });

  // Plenty of servers reject or mishandle HEAD — 405 and 501 are the correct
  // answers, but 403 and 400 from a WAF are common too. Retry with GET on any
  // client error so the check sees what a browser would actually receive.
  if (result.response.status >= 400 && result.response.status < 500) {
    await result.response.body?.cancel();
    method = "GET";
    result = await safeFetch(origin, { method, signal });
  }

  // Grade headers ONLY from a successful response.
  //
  // An error page — a WAF block, a 404, a 500 — routinely omits the security
  // headers the real site sends. Grading one would produce a full set of
  // confident "no CSP", "no HSTS" findings that are simply false about the
  // domain. Reporting the check as inconclusive is the honest outcome, and it
  // also excludes it from the score rather than tanking it on bad data.
  if (result.response.status < 200 || result.response.status >= 400) {
    await result.response.body?.cancel();
    return {
      check: CHECK,
      status: "error",
      reason: `${result.finalUrl} answered HTTP ${result.response.status}, so its response headers do not represent the site's security posture. Header grading was skipped rather than reported from an error page.`,
      findings: [],
      data: {
        finalUrl: result.finalUrl,
        status: result.response.status,
        method,
        hops: result.hops,
        headers: collectHeaders(result.response),
        httpRedirectsToHttps: null,
        httpRedirectNote: null,
      },
      durationMs: Date.now() - started,
    };
  }

  const headers = collectHeaders(result.response);
  await result.response.body?.cancel();

  const httpRedirect = await checkHttpRedirect(hostname, signal);

  const findings: Finding[] = [];

  // ---- HSTS ---------------------------------------------------------------
  const hstsRaw = headers["strict-transport-security"];
  if (!hstsRaw) {
    findings.push({
      id: "headers.hsts.missing",
      check: CHECK,
      severity: "medium",
      title: "No Strict-Transport-Security header",
      observed: `${result.finalUrl} responded without an HSTS header.`,
      impact:
        "Browsers will try plain http on a first visit or a typed address, leaving a window for an on-path attacker to intercept or downgrade the connection before the redirect happens.",
      remediation: {
        summary: "Send HSTS on every HTTPS response.",
        headerLine: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        reference: "RFC 6797",
      },
    });
  } else {
    const hsts = parseHsts(hstsRaw);

    if (hsts.maxAge === null || hsts.maxAge === 0) {
      findings.push({
        id: "headers.hsts.disabled",
        check: CHECK,
        severity: "medium",
        title: "HSTS is present but disabled",
        observed: `Strict-Transport-Security: ${hstsRaw}`,
        impact:
          "A max-age of 0 tells browsers to forget the HSTS policy immediately, which is equivalent to not sending it at all.",
        remediation: {
          summary: "Set a non-zero max-age.",
          headerLine: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
          reference: "RFC 6797",
        },
      });
    } else if (hsts.maxAge < HSTS_MIN_MAX_AGE) {
      findings.push({
        id: "headers.hsts.short",
        check: CHECK,
        severity: "low",
        title: "HSTS max-age is short",
        observed: `Strict-Transport-Security: ${hstsRaw} (max-age=${hsts.maxAge}s)`,
        impact: `A max-age below ${HSTS_MIN_MAX_AGE}s means the protection lapses sooner for visitors who do not return often.`,
        remediation: {
          summary: "Raise max-age to at least one year.",
          headerLine: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
          reference: "RFC 6797",
        },
      });
    } else {
      findings.push({
        id: "headers.hsts.ok",
        check: CHECK,
        severity: "pass",
        title: "HSTS is set with a long max-age",
        observed: `Strict-Transport-Security: ${hstsRaw}`,
        impact: "Browsers refuse to talk to this host over plain http for the stated duration.",
      });
    }

    if (hsts.maxAge && hsts.maxAge > 0 && !hsts.includeSubDomains) {
      findings.push({
        id: "headers.hsts.no-subdomains",
        check: CHECK,
        severity: "low",
        title: "HSTS does not cover subdomains",
        observed: `Strict-Transport-Security: ${hstsRaw}`,
        impact:
          "Subdomains are not protected, so an attacker who can reach a subdomain over http may still be able to set cookies or intercept traffic for it.",
        remediation: {
          summary: "Add includeSubDomains once every subdomain is HTTPS-only.",
          headerLine: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        },
      });
    }
  }

  // ---- CSP ----------------------------------------------------------------
  const csp = headers["content-security-policy"];
  if (!csp) {
    findings.push({
      id: "headers.csp.missing",
      check: CHECK,
      severity: "medium",
      title: "No Content-Security-Policy header",
      observed: `${result.finalUrl} responded without a CSP.`,
      impact:
        "Nothing constrains where scripts, styles and frames may load from, so an injected script runs with the page's full privileges.",
      remediation: {
        summary:
          "Add a CSP. Start in report-only mode to find what breaks, then enforce it.",
        headerLine:
          "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
        reference: "https://developer.mozilla.org/docs/Web/HTTP/CSP",
      },
    });
  } else {
    const unsafeInline = /'unsafe-inline'/i.test(csp);
    const unsafeEval = /'unsafe-eval'/i.test(csp);

    if (unsafeInline || unsafeEval) {
      const weaknesses = [
        unsafeInline ? "'unsafe-inline'" : null,
        unsafeEval ? "'unsafe-eval'" : null,
      ].filter((entry): entry is string => entry !== null);

      findings.push({
        id: "headers.csp.unsafe",
        check: CHECK,
        severity: "low",
        title: `CSP allows ${weaknesses.join(" and ")}`,
        observed: `Content-Security-Policy: ${csp.slice(0, 300)}${csp.length > 300 ? "…" : ""}`,
        impact:
          "These directives restore much of what CSP is meant to prevent: 'unsafe-inline' permits injected inline scripts to run, and 'unsafe-eval' permits string-to-code execution.",
        remediation: {
          summary:
            "Replace 'unsafe-inline' with per-request nonces or hashes, and remove 'unsafe-eval'.",
          reference: "https://developer.mozilla.org/docs/Web/HTTP/CSP",
        },
      });
    } else {
      findings.push({
        id: "headers.csp.ok",
        check: CHECK,
        severity: "pass",
        title: "Content-Security-Policy is set",
        observed: `Content-Security-Policy: ${csp.slice(0, 300)}${csp.length > 300 ? "…" : ""}`,
        impact: "Script and resource loading is constrained to an explicit allowlist.",
      });
    }
  }

  // ---- Framing ------------------------------------------------------------
  const xfo = headers["x-frame-options"];
  const frameAncestors = csp ? /frame-ancestors/i.test(csp) : false;

  if (!xfo && !frameAncestors) {
    findings.push({
      id: "headers.framing.missing",
      check: CHECK,
      severity: "medium",
      title: "No clickjacking protection",
      observed:
        "Neither X-Frame-Options nor a CSP frame-ancestors directive was returned.",
      impact:
        "The page can be embedded in an attacker's iframe and overlaid, so a victim's clicks can be redirected to actions they did not intend.",
      remediation: {
        summary:
          "Set frame-ancestors in your CSP (modern equivalent), and X-Frame-Options for older browsers.",
        headerLine: "Content-Security-Policy: frame-ancestors 'none'",
      },
    });
  } else {
    findings.push({
      id: "headers.framing.ok",
      check: CHECK,
      severity: "pass",
      title: "Clickjacking protection is set",
      observed: frameAncestors
        ? "CSP includes a frame-ancestors directive."
        : `X-Frame-Options: ${xfo}`,
      impact: "Embedding the page in a third-party frame is restricted.",
    });
  }

  // ---- Simple presence headers -------------------------------------------
  const xcto = headers["x-content-type-options"];
  if (!xcto || xcto.toLowerCase().trim() !== "nosniff") {
    findings.push({
      id: "headers.xcto.missing",
      check: CHECK,
      severity: "low",
      title: "X-Content-Type-Options is not set to nosniff",
      observed: xcto ? `X-Content-Type-Options: ${xcto}` : "Header not present.",
      impact:
        "Browsers may MIME-sniff a response and treat it as a type it was not declared to be, which can turn an uploaded file into executable script.",
      remediation: {
        summary: "Send the header on every response.",
        headerLine: "X-Content-Type-Options: nosniff",
      },
    });
  } else {
    findings.push({
      id: "headers.xcto.ok",
      check: CHECK,
      severity: "pass",
      title: "X-Content-Type-Options: nosniff",
      observed: "X-Content-Type-Options: nosniff",
      impact: "Browsers honour the declared content type instead of guessing.",
    });
  }

  if (!headers["referrer-policy"]) {
    findings.push({
      id: "headers.referrer-policy.missing",
      check: CHECK,
      severity: "low",
      title: "No Referrer-Policy header",
      observed: "Header not present.",
      impact:
        "Full URLs — including any path or query data — may be sent to third-party sites in the Referer header when users follow links.",
      remediation: {
        summary: "Set a conservative referrer policy.",
        headerLine: "Referrer-Policy: strict-origin-when-cross-origin",
      },
    });
  } else {
    findings.push({
      id: "headers.referrer-policy.ok",
      check: CHECK,
      severity: "pass",
      title: "Referrer-Policy is set",
      observed: `Referrer-Policy: ${headers["referrer-policy"]}`,
      impact: "Referrer disclosure to other origins is constrained.",
    });
  }

  if (!headers["permissions-policy"]) {
    findings.push({
      id: "headers.permissions-policy.missing",
      check: CHECK,
      severity: "low",
      title: "No Permissions-Policy header",
      observed: "Header not present.",
      impact:
        "Powerful browser features (camera, microphone, geolocation) are not explicitly denied to the page or to anything it embeds.",
      remediation: {
        summary: "Deny the features your site does not use.",
        headerLine: "Permissions-Policy: camera=(), microphone=(), geolocation=()",
      },
    });
  } else {
    findings.push({
      id: "headers.permissions-policy.ok",
      check: CHECK,
      severity: "pass",
      title: "Permissions-Policy is set",
      observed: `Permissions-Policy: ${headers["permissions-policy"]}`,
      impact: "Access to powerful browser features is explicitly scoped.",
    });
  }

  // ---- Version disclosure -------------------------------------------------
  for (const header of ["server", "x-powered-by"] as const) {
    const value = headers[header];
    if (value && leaksVersion(value)) {
      findings.push({
        id: `headers.disclosure.${header}`,
        check: CHECK,
        severity: "low",
        title: `${header === "server" ? "Server" : "X-Powered-By"} header discloses a version`,
        observed: `${header}: ${value}`,
        impact:
          "Naming the exact software version tells an attacker which published vulnerabilities to try first. It does not create a vulnerability by itself.",
        remediation: {
          summary: `Remove the version from the ${header} header, or drop the header entirely.`,
          headerLine: header === "server" ? "Server: (omit or send a bare product name)" : "X-Powered-By: (remove this header)",
        },
      });
    }
  }

  // ---- http -> https ------------------------------------------------------
  if (httpRedirect.redirects === false) {
    findings.push({
      id: "headers.http-no-redirect",
      check: CHECK,
      severity: "medium",
      title: "http:// does not redirect to https://",
      observed: `A plain HTTP request to http://${hostname}/ did not end up on https.`,
      impact:
        "Visitors who type the bare domain can be served over an unencrypted connection, which an on-path attacker can read or modify.",
      remediation: {
        summary: "Redirect all http traffic to https with a 301 before serving anything.",
        headerLine: "Location: https://" + hostname + "/",
      },
    });
  } else if (httpRedirect.redirects === true) {
    findings.push({
      id: "headers.http-redirects",
      check: CHECK,
      severity: "pass",
      title: "http:// redirects to https://",
      observed: `http://${hostname}/ redirects to HTTPS.`,
      impact: "Visitors arriving over plain HTTP are moved to an encrypted connection.",
    });
  }

  return {
    check: CHECK,
    status: "ok",
    findings,
    data: {
      finalUrl: result.finalUrl,
      status: result.response.status,
      method,
      hops: result.hops,
      headers,
      httpRedirectsToHttps: httpRedirect.redirects,
      httpRedirectNote: httpRedirect.note,
    },
    durationMs: Date.now() - started,
  };
}
