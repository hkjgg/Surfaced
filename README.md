# Surfaced

A public attack-surface scanner for company domains.

Enter a domain; Surfaced runs **passive, non-intrusive checks against publicly
available data only** — DNS records (SPF, DKIM, DMARC, DNSSEC, MX), HTTP
security headers, TLS certificate posture, and Certificate Transparency logs —
then returns a scored report with prioritised findings.

Surfaced never port scans, never probes for vulnerabilities, and never touches
a target's systems intrusively. See `CLAUDE.md` for the full constraint.

## Status

Foundation and design system. The scanner itself is not built yet.
