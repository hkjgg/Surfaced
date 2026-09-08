/**
 * Drives POST /api/scan against a running Surfaced server and prints the raw
 * JSON report for each target.
 *
 * Deliberately dependency-free and HTTP-driven: it exercises the route, the
 * validator, the orchestrator and the scoring exactly as deployed, rather
 * than importing the modules and testing something the server never runs.
 *
 *   npm run build && npm start &
 *   node scripts/verify-scanner.mjs [baseUrl] [phase]
 *
 * Phases exist because malformed and rejected requests still consume
 * rate-limit budget, and the whole point of the "limits" phase is to exhaust
 * it. Run them against separately started servers:
 *
 *   node scripts/verify-scanner.mjs http://127.0.0.1:3000 scans
 *   # restart the server, then
 *   node scripts/verify-scanner.mjs http://127.0.0.1:3000 limits
 */

const BASE = process.argv[2] ?? "http://127.0.0.1:3000";
const PHASE = process.argv[3] ?? "scans";

/** Targets, with what each one is here to demonstrate. */
const TARGETS = [
  ["neverssl.com", "no SPF, no DMARC, no MX"],
  ["example.com", "SPF -all, DMARC p=reject, RFC 7505 null MX"],
  ["github.com", "strong posture, different configuration"],
  ["google.com", "strong posture, different configuration"],
  ["pypi.org", "hardened real site: HSTS preload, CSP frame-ancestors, nosniff"],
  ["proxy.golang.org", "real site, partial headers, serves plain HTTP without redirecting"],
  ["registry.npmjs.org", "real site with no security headers on this endpoint"],
  ["192.168.1.1", "must be REJECTED (private address)"],
  ["not-a-real-domain-xyz123.com", "must fail gracefully (unresolvable)"],
];

const summarise = (report) => {
  const lines = [];
  lines.push(`  score: ${report.score.value ?? "null"}${report.score.partial ? " (PARTIAL)" : ""}`);
  lines.push(`  included: ${report.score.checksIncluded.join(", ") || "none"}`);
  lines.push(`  excluded: ${report.score.checksExcluded.join(", ") || "none"}`);
  for (const check of report.checks) {
    lines.push(`  ${check.check}: ${check.status}${check.reason ? ` — ${check.reason}` : ""} (${check.durationMs}ms)`);
    for (const f of check.findings) lines.push(`      [${f.severity.toUpperCase()}] ${f.id} — ${f.title}`);
  }
  return lines.join("\n");
};

let exitCode = 0;

if (PHASE === "scans") {
for (const [domain, intent] of TARGETS) {
  console.log("\n" + "=".repeat(78));
  console.log(`TARGET: ${domain}   —   ${intent}`);
  console.log("=".repeat(78));

  const started = Date.now();
  let response;
  try {
    response = await fetch(`${BASE}/api/scan`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain }),
    });
  } catch (error) {
    console.log(`REQUEST FAILED: ${error.message}`);
    exitCode = 1;
    continue;
  }

  const body = await response.json();
  console.log(`HTTP ${response.status} in ${Date.now() - started}ms`);

  if (response.status === 429) {
    console.log("Rate limit budget exhausted. Restart the server to continue this phase.");
    exitCode = 1;
    break;
  }

  if (!response.ok) {
    console.log(JSON.stringify(body, null, 2));
    continue;
  }

  console.log(summarise(body));
  console.log("--- full JSON ---");
  console.log(JSON.stringify(body, null, 2));
}
}

if (PHASE === "limits") {
console.log("=".repeat(78));
console.log("MALFORMED REQUESTS");
console.log("=".repeat(78));
for (const [label, init] of [
  ["not JSON", { method: "POST", body: "{" }],
  ["missing domain", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }],
  ["domain not a string", { method: "POST", headers: { "content-type": "application/json" }, body: '{"domain":123}' }],
]) {
  const r = await fetch(`${BASE}/api/scan`, init);
  console.log(`  ${label.padEnd(20)} -> HTTP ${r.status} ${JSON.stringify(await r.json())}`);
}

console.log("\n" + "=".repeat(78));
console.log("RATE LIMIT / CACHE");
console.log("=".repeat(78));
for (const label of ["first scan", "repeat scan"]) {
  const r = await fetch(`${BASE}/api/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ domain: "example.com" }),
  });
  console.log(`${label.padEnd(12)} of example.com -> HTTP ${r.status}, x-cache: ${r.headers.get("x-cache")}, remaining: ${r.headers.get("x-ratelimit-remaining")}`);
}

for (let i = 0; i < 12; i += 1) {
  const r = await fetch(`${BASE}/api/scan`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ domain: "example.com" }),
  });
  if (r.status === 429) {
    console.log(`rate limited after ${i + 1} further requests -> HTTP 429, retry-after: ${r.headers.get("retry-after")}s`);
    console.log(JSON.stringify(await r.json(), null, 2));
    break;
  }
}
}

process.exit(exitCode);
