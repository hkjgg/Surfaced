/**
 * Drives POST /api/scan against a running Surfaced server and prints the raw
 * JSON report for each target.
 *
 * Deliberately dependency-free and HTTP-driven: it exercises the route, the
 * validator, the orchestrator and the scoring exactly as deployed, rather
 * than importing the modules and testing something the server never runs.
 *
 *   npm run build && npm start &
 *   node scripts/verify-scanner.mjs [baseUrl]
 */

const BASE = process.argv[2] ?? "http://127.0.0.1:3000";

/** Targets, with what each one is here to demonstrate. */
const TARGETS = [
  ["neverssl.com", "no SPF, no DMARC, no MX"],
  ["example.com", "SPF -all, DMARC p=reject, RFC 7505 null MX"],
  ["github.com", "strong posture, live security headers"],
  ["google.com", "strong posture, different configuration"],
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

// Run these first: malformed requests still consume rate-limit budget, so
// asserting them after the scans would only ever demonstrate a 429.
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

  if (!response.ok) {
    console.log(JSON.stringify(body, null, 2));
    continue;
  }

  console.log(summarise(body));
  console.log("--- full JSON ---");
  console.log(JSON.stringify(body, null, 2));
}

console.log("\n" + "=".repeat(78));
console.log("RATE LIMIT / CACHE");
console.log("=".repeat(78));
const first = await fetch(`${BASE}/api/scan`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ domain: "example.com" }),
});
console.log(`repeat scan of example.com -> HTTP ${first.status}, x-cache: ${first.headers.get("x-cache")}, remaining: ${first.headers.get("x-ratelimit-remaining")}`);

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

process.exit(exitCode);
