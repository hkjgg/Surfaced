# `lib/scanner`

The scanning engine. Every module here reads **publicly available data only**.

## Layout

| File | Role |
|---|---|
| `types.ts` | `ScanReport`, `CheckResult`, `Finding`, `Remediation`. The only place shared types are declared. |
| `validate.ts` | The SSRF boundary. Normalises input and refuses anything that is not a public, publicly-addressed domain. |
| `email-auth.ts` | SPF (with RFC 7208 lookup counting), DKIM selector probing, DMARC. |
| `dns.ts` | NS, MX (including RFC 7505 null MX), SOA, DNSSEC. |
| `headers.ts` | HTTP response security headers. |
| `tls.ts` | Certificate posture from one standard handshake. |
| `ct.ts` | Certificate Transparency logs via crt.sh. |
| `exposure.ts` | Breach signal via Have I Been Pwned, or an explicit `not_configured`. |
| `orchestrate.ts` | Runs all six in parallel, isolates failures, caps total wall time. |
| `score.ts` | Weighted deductions. Checks that did not run are excluded from the denominator. |
| `internal/` | Shared plumbing: DNS resolver, DoH, timeouts, SSRF-aware fetch, DER certificate reading. |

Each check exports one async function taking a hostname and an `AbortSignal`
and returning a typed `CheckResult`. A check never throws to its caller for an
expected condition — a missing record is a finding, and an unreachable
dependency is an `error` status that excludes the check from scoring.

## What must never be added here

Surfaced is **strictly passive**. It reads public records about a target. The
strongest interaction permitted is a single, ordinary, well-behaved request of
the kind any browser makes when a person visits the site.

Never, under any circumstance:

- port scanning
- vulnerability probing, fuzzing, or payload injection of any kind
- authentication attempts, credential testing, or brute forcing
- directory or subdomain brute forcing
- traffic volume that could degrade a target, or any request pattern designed
  to evade rate limiting or detection

This is not a style preference. It is the constraint that makes Surfaced legal
to point at a domain you do not own. See `CLAUDE.md` §1.

## Two rules that are easy to break by accident

1. **Never report a guess as a fact.** A check that cannot reach its data
   source returns `error`, not a clean result. `dnssec.unknown` is not
   "unsigned"; `dkim.none-of-probed` is not "no DKIM"; an empty `p=` is a
   *revoked* key, not a published one. Every one of these was a real bug
   caught in verification, and each would have produced a confident, plausible,
   wrong answer.
2. **`validate.ts` is a security boundary, not formatting.** Anything reaching
   the network must have passed it — including every redirect hop, which
   `internal/fetcher.ts` re-validates individually.
