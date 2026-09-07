/**
 * SSRF boundary battery. Pure logic plus DNS — no external egress needed.
 */
import { validateHostnameSyntax, validateDomain, isPrivateAddress } from "../lib/scanner/validate.ts";

const MUST_REJECT = [
  "192.168.1.1", "127.0.0.1", "10.0.0.5", "172.16.0.1", "169.254.169.254",
  "100.64.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1",
  "2130706433", "0x7f000001", "0177.0.0.1",
  "[::1]", "[::ffff:127.0.0.1]", "[fe80::1]", "[fd00::1]",
  "localhost", "foo.local", "box.internal", "printer.lan", "x.home.arpa",
  "1.0.0.127.in-addr.arpa", "com", "co.uk", "singlelabel",
  "http://evil.com@127.0.0.1/", "https://user:pw@169.254.169.254/",
  "file:///etc/passwd", "gopher://x.com", "", "   ",
  "not_a_domain!!", "xn--", "site.invalid", "thing.test",
];

const MUST_ACCEPT = [
  ["example.com", "example.com"],
  ["https://example.com/path?q=1", "example.com"],
  ["EXAMPLE.COM", "example.com"],
  ["  github.com  ", "github.com"],
  ["sub.example.co.uk", "sub.example.co.uk"],
  ["bücher.de", "xn--bcher-kva.de"],
] as const;

let failures = 0;
console.log("=== must reject (syntax layer) ===");
for (const input of MUST_REJECT) {
  const r = validateHostnameSyntax(input);
  const ok = !r.ok;
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${JSON.stringify(input).padEnd(38)} -> ${r.ok ? "ACCEPTED " + r.hostname : r.code}`);
}

console.log("\n=== must accept + normalise ===");
for (const [input, expected] of MUST_ACCEPT) {
  const r = validateHostnameSyntax(input);
  const ok = r.ok && r.hostname === expected;
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${JSON.stringify(input).padEnd(30)} -> ${r.ok ? r.hostname : r.code} (expected ${expected})`);
}

console.log("\n=== isPrivateAddress ===");
const ADDR: [string, boolean][] = [
  ["8.8.8.8", false], ["1.1.1.1", false], ["140.82.121.4", false],
  ["127.0.0.1", true], ["10.1.2.3", true], ["172.31.255.255", true], ["172.32.0.1", false],
  ["192.168.0.1", true], ["169.254.169.254", true], ["100.64.0.1", true], ["100.128.0.1", false],
  ["::1", true], ["fe80::1", true], ["fd00::1", true], ["::ffff:10.0.0.1", true],
  ["2606:4700::1111", false], ["garbage", true],
];
for (const [addr, expected] of ADDR) {
  const got = isPrivateAddress(addr);
  const ok = got === expected;
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${addr.padEnd(22)} private=${got} (expected ${expected})`);
}

console.log("\n=== full validation (with DNS) ===");
for (const d of ["192.168.1.1", "not-a-real-domain-xyz123.com", "example.com"]) {
  const r = await validateDomain(d);
  console.log(`  ${d.padEnd(32)} -> ${r.ok ? `OK ${r.hostname} ${JSON.stringify(r.addresses)}` : `${r.code}: ${r.message}`}`);
}

console.log(failures === 0 ? "\nALL SSRF CHECKS PASS" : `\n${failures} FAILURE(S)`);
process.exit(failures === 0 ? 0 : 1);
