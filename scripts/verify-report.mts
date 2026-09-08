/**
 * Assertions for the report layer's pure logic, plus an optional live check
 * that the scan stream really streams.
 *
 *   npm run verify:report                      # pure logic only
 *   npm run verify:report -- http://127.0.0.1:3000   # also drives the server
 *
 * The remediation assertions are verbatim on purpose. These snippets get
 * pasted into production by people who trust them, so "looks about right" is
 * not a standard — the exact bytes are pinned here, and a change to them has
 * to be a deliberate edit to this file.
 */

import { remediationTargets } from "../lib/scanner/remediation.js";
import { axisScore, scoreBand } from "../lib/scanner/score.js";
import { applyFilters, parseFilters, serializeFilters } from "../lib/report/filters.js";
import type { CheckResult, Finding } from "../lib/scanner/types.js";

let failures = 0;

function check(label: string, actual: unknown, expected: unknown): void {
  const a = JSON.stringify(actual);
  const b = JSON.stringify(expected);

  if (a === b) {
    console.log(`  ok   ${label}`);
  } else {
    failures += 1;
    console.error(`  FAIL ${label}\n       expected ${b}\n       actual   ${a}`);
  }
}

function assert(label: string, condition: boolean): void {
  check(label, condition, true);
}

// ---------------------------------------------------------------------------
console.log("\nremediation → deployment forms");

const hsts = remediationTargets({
  summary: "Send HSTS on every HTTPS response.",
  headerLine: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
  reference: "RFC 6797",
});

check(
  "tab order",
  hsts.map((target) => target.id),
  ["header", "nginx", "apache", "cloudflare", "vercel"],
);

check(
  "raw header",
  hsts.find((t) => t.id === "header")?.code,
  "Strict-Transport-Security: max-age=31536000; includeSubDomains",
);

check(
  "nginx",
  hsts.find((t) => t.id === "nginx")?.code,
  'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
);

check(
  "apache",
  hsts.find((t) => t.id === "apache")?.code,
  'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
);

check(
  "cloudflare _headers",
  hsts.find((t) => t.id === "cloudflare")?.code,
  "# _headers — Cloudflare Pages\n/*\n  Strict-Transport-Security: max-age=31536000; includeSubDomains",
);

check(
  "vercel.json",
  hsts.find((t) => t.id === "vercel")?.code,
  `{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Strict-Transport-Security",
          "value": "max-age=31536000; includeSubDomains"
        }
      ]
    }
  ]
}`,
);

// A CSP value carries single quotes; they must survive into a double-quoted
// directive untouched, because 'self' and 'none' are literal CSP keywords.
const csp = remediationTargets({
  summary: "Add a CSP.",
  headerLine:
    "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'",
});

check(
  "csp nginx keeps single quotes",
  csp.find((t) => t.id === "nginx")?.code,
  `add_header Content-Security-Policy "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'" always;`,
);

console.log("\nremediation → forms that must NOT be generated");

check(
  "a header to REMOVE produces no snippet",
  remediationTargets({
    summary: "Remove the version from the x-powered-by header.",
    headerLine: "X-Powered-By: (remove this header)",
  }).length,
  0,
);

check(
  "a parenthetical instruction produces no snippet",
  remediationTargets({
    summary: "Omit the Server version.",
    headerLine: "Server: (omit or send a bare product name)",
  }).length,
  0,
);

check(
  "a redirect Location produces no blanket header",
  remediationTargets({
    summary: "Redirect http to https.",
    headerLine: "Location: https://example.com/",
  }).length,
  0,
);

check(
  "an action with no snippet produces none",
  remediationTargets({ summary: "Renew the certificate immediately." }).length,
  0,
);

console.log("\nremediation → DNS");

const spf = remediationTargets({
  summary: "Publish an SPF record.",
  dnsRecord: { name: "example.com", type: "TXT", value: "v=spf1 -all" },
});

check("single form, no tabs", spf.length, 1);
check("zone-file line", spf[0]?.code, 'example.com. IN TXT "v=spf1 -all"');

check(
  "MX value is not quoted",
  remediationTargets({
    summary: "Publish a null MX.",
    dnsRecord: { name: "example.com", type: "MX", value: "0 ." },
  })[0]?.code,
  "example.com. IN MX 0 .",
);

// RFC 1035 §3.3.14: one character-string cannot exceed 255 bytes.
const longValue = `v=DKIM1; k=rsa; p=${"A".repeat(400)}`;
const longRecord = remediationTargets({
  summary: "Publish the key.",
  dnsRecord: { name: "s._domainkey.example.com", type: "TXT", value: longValue },
})[0];

assert(
  "a >255 byte TXT value is split into multiple character-strings",
  (longRecord?.code.match(/"/g)?.length ?? 0) === 4,
);

// ---------------------------------------------------------------------------
console.log("\nscore bands");

check("100 → pass", scoreBand(100), "pass");
check("90 → pass", scoreBand(90), "pass");
check("89 → low", scoreBand(89), "low");
check("75 → low", scoreBand(75), "low");
check("74 → medium", scoreBand(74), "medium");
check("50 → medium", scoreBand(50), "medium");
check("49 → high", scoreBand(49), "high");
check("25 → high", scoreBand(25), "high");
check("24 → critical", scoreBand(24), "critical");
check("0 → critical", scoreBand(0), "critical");

console.log("\naxis scores");

const okCheck: CheckResult = {
  check: "headers",
  status: "ok",
  findings: [],
  durationMs: 1,
};

check("a clean check scores 100", axisScore(okCheck), 100);

check(
  "an errored check is null, not zero",
  axisScore({ ...okCheck, status: "error", reason: "timed out" }),
  null,
);

check(
  "an unconfigured check is null, not zero",
  axisScore({ ...okCheck, check: "exposure", status: "not_configured" }),
  null,
);

check("a missing check is null", axisScore(undefined), null);

check(
  "one critical finding consumes the whole axis",
  axisScore({
    ...okCheck,
    findings: [
      {
        id: "x",
        check: "headers",
        severity: "critical",
        title: "t",
        observed: "o",
        impact: "i",
      },
    ],
  }),
  0,
);

// ---------------------------------------------------------------------------
console.log("\nfilters");

const findings: Finding[] = (
  ["critical", "high", "medium", "low", "pass", "pass"] as const
).map((severity, index) => ({
  id: `f${index}`,
  check: "dns" as const,
  severity,
  title: "t",
  observed: "o",
  impact: "i",
}));

check(
  "no params → everything",
  applyFilters(findings, parseFilters(new URLSearchParams())).length,
  6,
);

check(
  "sev=critical,high",
  applyFilters(findings, parseFilters(new URLSearchParams("sev=critical,high"))).length,
  2,
);

check(
  "passed=0 hides passes",
  applyFilters(findings, parseFilters(new URLSearchParams("passed=0"))).length,
  4,
);

check(
  "an unknown severity is dropped, not fatal",
  parseFilters(new URLSearchParams("sev=critical,banana")).severities,
  ["critical"],
);

check(
  "an entirely unknown selection means show all",
  applyFilters(findings, parseFilters(new URLSearchParams("sev=banana"))).length,
  6,
);

check(
  "empty sev means show all, never show nothing",
  applyFilters(findings, parseFilters(new URLSearchParams("sev="))).length,
  6,
);

check(
  "round-trips to a canonical order",
  serializeFilters(parseFilters(new URLSearchParams("sev=low,critical"))).toString(),
  "sev=critical%2Clow",
);

check(
  "unrelated params survive serialisation",
  serializeFilters(
    { severities: ["high"], hidePassed: true },
    new URLSearchParams("ref=abc"),
  ).toString(),
  "ref=abc&sev=high&passed=0",
);

// ---------------------------------------------------------------------------
const base = process.argv[2];

if (base) {
  console.log(`\nlive stream against ${base}`);

  const target = process.argv[3] ?? "example.com";
  const started = Date.now();

  const response = await fetch(`${base}/api/scan`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "text/event-stream" },
    body: JSON.stringify({ domain: target }),
  });

  check("content-type is SSE", response.headers.get("content-type"), "text/event-stream; charset=utf-8");
  assert("no-transform is set", (response.headers.get("cache-control") ?? "").includes("no-transform"));

  const arrivals: { name: string; at: number; data: Record<string, unknown> }[] = [];
  const reader = response.body!.getReader();
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
      boundary = buffer.indexOf("\n\n");

      const name = /^event: (.+)$/m.exec(frame)?.[1];
      const payload = /^data: (.+)$/m.exec(frame)?.[1];
      if (name && payload) {
        arrivals.push({ name, at: Date.now() - started, data: JSON.parse(payload) });
      }
    }
  }

  const checks = arrivals.filter((entry) => entry.name === "check");

  check("one event per check", checks.length, 6);
  assert("a start event came first", arrivals[0]?.name === "start");
  assert("a report event came last", arrivals.at(-1)?.name === "report");

  // The point of the whole exercise: events must arrive as checks settle, not
  // all at once when the scan finishes. If the last check event lands at the
  // same moment as the first, the response was buffered somewhere and the
  // "live" terminal is a fiction.
  const first = checks[0]?.at ?? 0;
  const last = checks.at(-1)?.at ?? 0;
  const cached = (arrivals[0]?.data as { cached?: boolean }).cached === true;

  if (cached) {
    console.log("  --   spread not asserted: this was a cached replay");
  } else {
    assert(`check events are spread over time (${last - first}ms)`, last - first > 5);
  }

  // Each event's own elapsed stamp should track its arrival, within the
  // latency of one HTTP hop.
  for (const entry of checks) {
    const elapsed = entry.data.elapsedMs as number | undefined;
    if (elapsed === undefined) continue;
    assert(
      `${String(entry.data.check)} elapsedMs tracks arrival (${elapsed} vs ${entry.at})`,
      Math.abs(entry.at - elapsed) < 2000,
    );
  }
}

console.log(
  failures === 0 ? "\nAll report assertions passed.\n" : `\n${failures} assertion(s) FAILED.\n`,
);
process.exit(failures === 0 ? 0 : 1);
