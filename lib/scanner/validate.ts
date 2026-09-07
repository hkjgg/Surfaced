/**
 * The SSRF boundary.
 *
 * Everything downstream of this module makes outbound network requests to a
 * hostname the caller supplied. That makes this an access-control boundary,
 * not input formatting: if a hostname gets through that points at loopback,
 * RFC 1918 space, or a cloud metadata endpoint, the scanner becomes a proxy
 * for reaching things the caller could not reach directly.
 *
 * The rules therefore fail closed. Anything not positively established as a
 * public, resolvable, publicly-addressed domain name is rejected.
 */

import { isIP } from "node:net";

import { parse as parseDomain } from "tldts";

import { resolveAddresses } from "./internal/resolver";

export type RejectionCode =
  | "empty"
  | "malformed"
  | "too_long"
  | "ip_address"
  | "not_public_suffix"
  | "reserved_suffix"
  | "single_label"
  | "unresolvable"
  | "private_address";

export interface ValidationSuccess {
  readonly ok: true;
  /** Lowercased, punycode (IDNA) normalised hostname. */
  readonly hostname: string;
  /** Public addresses the hostname resolved to during validation. */
  readonly addresses: readonly string[];
}

export interface ValidationFailure {
  readonly ok: false;
  readonly code: RejectionCode;
  /** Safe to show a user; never echoes an unbounded input string. */
  readonly message: string;
}

export type ValidationResult = ValidationSuccess | ValidationFailure;

/** DNS names are capped at 253 characters. */
const MAX_HOSTNAME_LENGTH = 253;

/**
 * Suffixes that never denote a public internet host. `.arpa` covers
 * `in-addr.arpa` and `169.254.169.254.in-addr.arpa` style lookups.
 */
const RESERVED_SUFFIXES = [
  ".local",
  ".localhost",
  ".internal",
  ".intranet",
  ".private",
  ".corp",
  ".home",
  ".lan",
  ".home.arpa",
  ".arpa",
  ".onion",
  ".test",
  ".example",
  ".invalid",
];

const RESERVED_EXACT = ["localhost", "local"];

function fail(code: RejectionCode, message: string): ValidationFailure {
  return { ok: false, code, message };
}

/**
 * Extract a hostname from a bare domain or a full URL.
 *
 * Parsing through `URL` rather than a regex is deliberate: it performs IDNA
 * conversion (so `bücher.de` becomes `xn--bcher-kva.de`) and it strips
 * userinfo, so `https://evil.com@127.0.0.1/` yields `127.0.0.1` — the host a
 * request would actually reach — instead of the domain a regex would have
 * been fooled into reading.
 */
function extractHostname(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return null;
  }

  // Only http(s) inputs are meaningful here; anything else is a caller
  // trying to smuggle a different protocol through.
  if (url.protocol !== "https:" && url.protocol !== "http:") return null;

  // `URL` keeps IPv6 hosts in brackets; strip them so isIP() sees the address.
  const host = url.hostname.toLowerCase();
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

/**
 * True for any address that must never be reached on the caller's behalf.
 *
 * Covers loopback, RFC 1918, link-local (which includes the 169.254.169.254
 * cloud metadata endpoint), CGNAT, benchmarking, documentation, multicast,
 * broadcast, and IPv6 equivalents including IPv4-mapped forms.
 */
export function isPrivateAddress(address: string): boolean {
  const version = isIP(address);
  if (version === 4) return isPrivateIPv4(address);
  if (version === 6) return isPrivateIPv6(address);
  // Not a parseable address at all — treat as unsafe.
  return true;
}

function isPrivateIPv4(address: string): boolean {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n))) return true;

  const [a = 0, b = 0] = parts;

  if (a === 0) return true; // "this network"
  if (a === 10) return true; // RFC 1918
  if (a === 127) return true; // loopback
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT, RFC 6598
  if (a === 169 && b === 254) return true; // link-local + cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC 1918
  if (a === 192 && b === 0) return true; // IETF protocol assignments
  if (a === 192 && b === 168) return true; // RFC 1918
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a === 192 && b === 88) return true; // 6to4 relay anycast
  if (a >= 224) return true; // multicast, reserved, broadcast

  return false;
}

function isPrivateIPv6(address: string): boolean {
  const addr = address.toLowerCase().split("%")[0] ?? "";

  if (addr === "::" || addr === "::1") return true; // unspecified, loopback

  // IPv4-mapped (::ffff:127.0.0.1) and IPv4-compatible forms must be judged
  // by their embedded IPv4 address, not by their IPv6 prefix.
  const embedded = addr.match(/^::(?:ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (embedded?.[1]) return isPrivateIPv4(embedded[1]);

  if (addr.startsWith("fe8") || addr.startsWith("fe9")) return true; // link-local
  if (addr.startsWith("fea") || addr.startsWith("feb")) return true;
  if (addr.startsWith("fc") || addr.startsWith("fd")) return true; // unique-local
  if (addr.startsWith("ff")) return true; // multicast
  if (addr.startsWith("2001:db8")) return true; // documentation
  if (addr.startsWith("64:ff9b")) return true; // NAT64

  return false;
}

/**
 * Structural validation only — no DNS. Split out so it can be applied to
 * every redirect hop without paying for a resolve each time.
 */
export function validateHostnameSyntax(
  input: string,
): { ok: true; hostname: string } | ValidationFailure {
  if (!input || !input.trim()) return fail("empty", "Enter a domain to scan.");

  if (input.length > 2048) {
    return fail("too_long", "That input is too long to be a domain.");
  }

  const hostname = extractHostname(input);
  if (!hostname) {
    return fail("malformed", "That doesn't look like a domain or URL.");
  }

  if (hostname.length > MAX_HOSTNAME_LENGTH) {
    return fail("too_long", "That hostname is longer than DNS allows.");
  }

  // Reject IP literals before anything else. tldts also detects these, but
  // isIP covers the forms URL has already normalised (including the decimal
  // and hex notations browsers accept, e.g. 2130706433 -> 127.0.0.1).
  if (isIP(hostname) !== 0) {
    return fail(
      "ip_address",
      "Surfaced scans domain names, not IP addresses.",
    );
  }

  if (RESERVED_EXACT.includes(hostname)) {
    return fail("reserved_suffix", "That hostname is not a public domain.");
  }

  if (RESERVED_SUFFIXES.some((suffix) => hostname.endsWith(suffix))) {
    return fail(
      "reserved_suffix",
      "That domain uses a reserved suffix that never resolves publicly.",
    );
  }

  if (!hostname.includes(".")) {
    return fail("single_label", "Enter a full domain, like example.com.");
  }

  const parsed = parseDomain(hostname);

  // tldts flags IPs and non-ICANN suffixes. Requiring an ICANN suffix (rather
  // than accepting the private section of the PSL) keeps the target set to
  // names that exist in the public DNS hierarchy.
  if (parsed.isIp) {
    return fail("ip_address", "Surfaced scans domain names, not IP addresses.");
  }

  if (!parsed.publicSuffix || !parsed.domain || !parsed.isIcann) {
    return fail(
      "not_public_suffix",
      "That domain has no recognised public suffix.",
    );
  }

  // "com" or "co.uk" alone is a suffix, not a registrable domain.
  if (hostname === parsed.publicSuffix) {
    return fail(
      "not_public_suffix",
      "That's a public suffix, not a domain you can scan.",
    );
  }

  return { ok: true, hostname };
}

/**
 * Full validation: syntax, then resolution, then address vetting.
 *
 * Rejects if *any* returned address is private, not merely if all of them
 * are. A name resolving to both a public and a private address is the exact
 * shape of a rebinding attack, so a mixed answer is treated as hostile.
 *
 * Known limitation: this resolves, and the checks resolve again when they
 * connect. That TOCTOU gap cannot be fully closed without pinning the address
 * and overriding SNI/Host, which would break every CDN-hosted site. It is
 * narrowed by re-validating each redirect hop in internal/fetcher.ts.
 */
export async function validateDomain(
  input: string,
  signal?: AbortSignal,
): Promise<ValidationResult> {
  const syntax = validateHostnameSyntax(input);
  if (!syntax.ok) return syntax;

  const { hostname } = syntax;

  let addresses: readonly string[];
  try {
    addresses = await resolveAddresses(hostname, signal);
  } catch {
    return fail(
      "unresolvable",
      "That domain doesn't resolve. Check the spelling.",
    );
  }

  if (addresses.length === 0) {
    return fail(
      "unresolvable",
      "That domain has no A or AAAA records, so there is nothing to reach.",
    );
  }

  if (addresses.some(isPrivateAddress)) {
    return fail(
      "private_address",
      "That domain resolves to a private or reserved address.",
    );
  }

  return { ok: true, hostname, addresses };
}
