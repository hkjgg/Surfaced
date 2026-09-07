# `lib/scanner` — reserved

Intentionally empty. The scanning engine lands here in a later step; this
directory exists now so that the boundary is established before any code is
written, rather than negotiated afterwards.

## What belongs here

Passive collection and scoring against **publicly available data only**:

- DNS record lookups — SPF, DKIM, DMARC, DNSSEC, MX
- HTTP response security headers
- TLS certificate posture
- Certificate Transparency log queries
- Finding construction and scoring, using the `Severity` scale from
  `lib/severity.ts`

## What must never be added here

Surfaced is **strictly passive**. It reads public records about a target; it
does not interact with the target's systems beyond an ordinary, single,
well-behaved request that any browser would make.

Never, under any circumstance:

- port scanning
- vulnerability probing, fuzzing, or payload injection of any kind
- authentication attempts, credential testing, or brute forcing
- directory or subdomain brute forcing
- traffic volume that could degrade a target, or any request pattern designed
  to evade rate limiting or detection

This is not a style preference. It is the constraint that makes Surfaced legal
to point at a domain you do not own. See `CLAUDE.md`.
