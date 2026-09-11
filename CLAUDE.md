# Surfaced

A public attack-surface scanner for company domains. A visitor enters a domain;
Surfaced runs passive checks against publicly available data and returns a
scored report with prioritised findings.

---

## 1. The passive-only constraint — a hard rule

**Surfaced is strictly passive. This is not a preference, a default, or a
current phase. It is the constraint that makes the product legal to point at a
domain nobody has asked permission to test.**

Surfaced may read **publicly available data only**:

- DNS records — SPF, DKIM, DMARC, DNSSEC, MX
- HTTP response security headers
- TLS certificate posture
- Certificate Transparency logs

The strongest interaction permitted with a target is a single, ordinary,
well-behaved HTTPS request of the kind any browser makes when a person visits
the site — sent to fetch response headers, at normal volume, identifying
itself honestly.

**Never add, and never accept a request to add:**

- port scanning of any kind
- vulnerability probing, fuzzing, or payload injection
- authentication attempts, credential testing, or brute forcing
- directory, path, or subdomain brute forcing
- request volume that could degrade a target
- any request pattern designed to evade rate limiting, filtering, or detection

If a feature request cannot be satisfied from public records, the answer is
that Surfaced does not do it. Do not implement it behind a flag, an opt-in, a
"you own this domain" checkbox, or an admin-only route. Self-attestation of
ownership is not verification, and an unverified checkbox is not consent.

The product copy in the footer states this to users. Keep the code and the
promise in agreement.

### The corollary: never report a guess as a fact

A scanner that returns plausible-looking wrong answers is worse than no
scanner, because people act on it. So a check that cannot reach its data
source returns `error` and is excluded from the score — it never falls back to
a clean result. Specifically:

- `dnssec.unknown` is not "unsigned" — a failed DS lookup is not a fact about
  the domain.
- Finding no DKIM key at the probed selectors is not "DKIM is missing".
  Selectors are not enumerable from DNS, so absence proves nothing.
- An empty `p=` in a DKIM record is a **revoked** key (RFC 6376 §3.6.1), not a
  published one.
- Security headers are graded only from a successful response. A WAF's 400 or
  a 404 page routinely lacks the headers the real site sends.
- A subdomain with no NS records of its own is normally delegated, not broken.
  Delegation lives at the zone apex.
- A subdomain with no DMARC record of its own is not unprotected: DMARC falls
  back to the organizational domain, with `sp=` taking precedence over `p=`
  (RFC 7489 §6.6.3). Check the parent before reporting anything.

Each of these was a real bug found during verification, and each would have
produced a confident, plausible, wrong answer.

---

## 2. Stack

| Concern | Choice | Notes |
|---|---|---|
| Framework | Next.js 15 (App Router) | Pinned to `15.5.25`, not 16 |
| Language | TypeScript, `strict` | Plus `noUncheckedIndexedAccess` |
| Styling | Tailwind CSS v4 | CSS-first. **No `tailwind.config.ts`** |
| Fonts | `geist` npm package | Local files — no network fetch at build |
| Database | Supabase | Wired up, **currently unused** |
| Hosting | Vercel | |

Tailwind v4 is configured entirely in `app/globals.css` via `@theme`. Adding a
`tailwind.config.ts` would split the source of truth — don't.

`geist` is used instead of `next/font/google` on purpose: it ships font files
in the package, so builds work offline and in a cold CI container.

### Commands

```bash
npm run dev              # dev server
npm run build            # production build (must pass with NO env vars)
npm run lint             # eslint
npm run typecheck        # tsc --noEmit
npm run check:contrast   # assert the palette still clears WCAG AA
npm run verify:ssrf      # SSRF boundary battery (pure logic + DNS)
npm run verify:scanner   # drive POST /api/scan against a running server
npm run verify:report    # remediation snippets, score bands, filters, site URL
                         # pass a base URL to also assert the scan streams
npm run verify:ct        # the crt.sh retry, through an injected fetcher
```

`scripts/screenshot-report.mjs` captures the report at 375px and 1280px. It
needs Playwright, which is deliberately **not** a dependency — point it at an
existing install with `PLAYWRIGHT_PATH`.

---

## 3. Folder conventions

```
app/                  routes, layout, globals.css. Server Components by default.
components/ui/        presentational primitives. No data fetching, no scanner
                      imports, no business logic. If it needs to know what a
                      DNS record is, it does not belong here.
components/layout/    app shell: header, footer, wordmark.
components/report/    the report UI. These DO know what a DNS record is, so
                      they live here rather than in ui/. They compose the ui/
                      primitives; they never restyle them. tone.ts holds the
                      severity -> class maps, in one place so they cannot drift.
lib/scanner/          the scanning engine: one module per check, plus
                      orchestrate.ts, score.ts, validate.ts and types.ts.
                      internal/ holds shared plumbing. See its README.
lib/supabase/         env validation + client factories.
lib/report/           report-layer logic that is pure and testable outside a
                      browser — currently the URL filter state.
lib/scan-facts.ts     figures the marketing surface may state, each derived
                      from code or carrying its provenance in a comment.
lib/site-url.ts       the deployment's own origin, validated. Feeds
                      metadataBase; returns null when unset.
assets/               one font file, for next/og. See assets/README.md.
lib/severity.ts       the severity scale. Single source of truth.
lib/cn.ts             className merge helper.
scripts/              repo checks that are not app code.
```

Rules:

- `components/ui` may not import from `lib/scanner`. Presentation stays
  reusable and testable without the engine.
- Add `"use client"` only where interactivity genuinely requires it. `Input`
  is a client component because it calls `useId`; `Button`, `Card`, `Badge`,
  `Skeleton` and `Callout` are deliberately server-safe.
- Import via the `@/` alias.

---

## 4. Environment variables

**The build must succeed with no environment variables set.** CI, a fresh
clone, and a preview deploy with an empty environment must all produce a
working build. Verify with:

```bash
env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$HOME" sh -c 'npm run build'
```

Two rules follow from this:

1. **Never construct a URL from an unvalidated environment variable.** Parse it
   with `new URL()` inside a `try/catch`, require the expected protocol, and
   use the parsed result — never the raw string, and never string
   concatenation. An unvalidated env var interpolated into a request target is
   how credentials get sent to the wrong host. `lib/supabase/env.ts` is the
   pattern to copy.
2. **Never read config at module scope.** Client factories are functions that
   return `null` when unconfigured, so importing them during a build is inert.
   Callers must handle `null`; there is no non-null variant.

All three variables are optional: the two Supabase ones, and `HIBP_API_KEY`
for the exposure check. `.env.example` documents them. With no HIBP key the
exposure check returns `not_configured`, which is excluded from scoring — it
must never be reported as a pass, because "we did not look" and "we looked and
it was clean" are different facts.

### The site URL, and why `metadataBase` now exists

Open Graph needs absolute URLs, so the app has to know its own origin — the one
thing it can only learn from the environment. `lib/site-url.ts` reads
`NEXT_PUBLIC_SITE_URL`, falling back to Vercel's
`VERCEL_PROJECT_PRODUCTION_URL`, and returns `null` when neither is usable; the
build then simply omits `metadataBase`. This supersedes the earlier "no
metadataBase at all" note, which was right while nothing needed an absolute URL.

The Vercel variable is a **bare hostname**, and it is matched against a strict
hostname pattern *before* a scheme is attached. Prefixing `https://` onto an
unvalidated string is the concatenation rule 1 forbids: `evil.com/@surfaced.app`
parses into a URL whose host is `evil.com` while reading as though it were not.
`verify:report` pins that case and several others.

---

## 5. Design system

Intent: **a serious engineering tool — closer to a terminal or an
observability dashboard than a marketing site. Restraint over decoration.**

All tokens live in `app/globals.css` under `@theme`. Tailwind generates the
utilities (`--color-critical` → `text-critical`, `bg-critical`,
`border-critical`). Never hard-code a hex value in a component.

### Surfaces

Near-black with a cool cast, never pure black. Elevation on a dark UI comes
from surface lightness plus a hairline border first; shadow is secondary.

| Token | Value |
|---|---|
| `--color-bg` | `#0a0b0d` |
| `--color-surface` | `#111316` |
| `--color-raised` | `#181b1f` |
| `--color-overlay` | `#1e2227` |
| `--color-border` | `#24282e` |
| `--color-border-strong` | `#343a42` |

### Foreground

| Token | Value | On `--color-bg` |
|---|---|---|
| `--color-fg` | `#e8eaed` | 16.3:1 |
| `--color-fg-muted` | `#a8b0ba` | 9.0:1 |
| `--color-fg-subtle` | `#8b939e` | 6.3:1 |
| `--color-fg-invert` | `#0a0b0d` | for text on an accent fill |

### Accent — one colour, used sparingly

`--color-accent` `#8e81f7` (dim `#7a6df4`, plus `-wash` and `-edge` tints).

Reserved for: focus rings, the single primary action, active/selected state,
and the score readout. It sits deliberately **outside** the severity ramp so
emphasis is never mistaken for a finding. If the accent is the largest thing on
screen, that is a bug — see the `Scan` button, which is intentionally natural
width rather than full-bleed on mobile.

**The one deliberate exception: the score gauge.** Its **arc** is banded with
the severity ramp (`scoreBand()` in `score.ts`), while the **numeral** keeps
the accent. The arc states a verdict, so it should read as one at a glance; the
number stays the page's single accent anchor. Both channels are backed by text
— the band label and its rank meter sit beside the number — so the verdict
never depends on colour. `check:contrast` asserts each arc colour clears 3:1
against both the gauge track and the surface behind it.

Note that the gauge uses its own wording for the bands, not `SEVERITY[].label`.
"89 · LOW" invites exactly the wrong reading; "89 · MINOR ISSUES" does not. The
colour and the meter still come from the ramp — only the words change.

### Severity scale

**Colour is the secondary channel.** The primary channel is the rank meter plus
the uppercase label, so severity survives greyscale, a monochrome display, and
any colour-vision deficiency. `<Badge variant="high" />` renders both
automatically. **Never render severity as a bare colour swatch.**

| Rank | Token | Value | Meter |
|---|---|---|---|
| critical | `--color-critical` | `#f2555a` | `▮▮▮▮` |
| high | `--color-high` | `#ff8a3d` | `▮▮▮▯` |
| medium | `--color-medium` | `#e3b341` | `▮▮▯▯` |
| low | `--color-low` | `#58a6ff` | `▮▯▯▯` |
| pass | `--color-pass` | `#3fb950` | `✓` |

Each has `-wash` (fill) and `-edge` (border) variants. `lib/severity.ts` is the
single source of truth for labels, meters, ordering and meanings — including
`pass`, which stays in the scale because a report that only lists problems
gives no evidence that anything was checked.

### The radar's six axes

`SCORE_AXES` in `lib/scanner/score.ts` maps display axes to checks. One pairing
is genuinely confusing and is worth reading before touching either:

| Axis label | Check module |
|---|---|
| Email | `email-auth.ts` |
| DNS | `dns.ts` |
| TLS | `tls.ts` |
| Headers | `headers.ts` |
| **Exposure** | **`ct.ts`** — what the domain exposes in public CT logs |
| **Breaches** | **`exposure.ts`** — the HIBP breach check |

The label "Exposure" and the file `exposure.ts` are **not** the same thing. The
modules keep their names; `SCORE_AXES` is the mapping.

Per-axis subscores come from `axisScore()`, which reuses the same weights and
deductions as the total, so an axis can never disagree with the headline score.
An axis whose check did not run returns `null` and renders as an explicit gap —
never a zero, which would claim the domain failed something nobody looked at.

### Type

- `--font-sans` (Geist Sans) — prose and headings.
- `--font-mono` (Geist Mono) — **domains, DNS records, HTTP headers, metrics,
  technical labels, the wordmark.** Mono is not decoration here; it marks a
  string as machine-readable and comparable character by character.

Scale is dense and tool-like: base is 15px, not 16px. `--text-2xs` (11px)
through `--text-4xl`, with `3xl`/`4xl` fluid via `clamp()`. Tracking tokens:
`--tracking-display`, `--tracking-tight`, `--tracking-label`.

### Spacing, radii, elevation

Tailwind's 4px base, plus named page rhythm (`--spacing-gutter`,
`--spacing-section`, `--spacing-section-lg`). Radii are tight —
`2 / 4 / 6 / 10 / 14px` — because tight corners read as tooling and soft
corners read as SaaS. Elevation is `--shadow-1` through `--shadow-3`, all
low-alpha.

### Custom utilities

- `label` — the recurring uppercase mono micro-label (card eyebrows, severity
  labels, table headers).
- `shell` — the page container, with a gutter that holds at 375px.
- `dot-matrix` — the home page's dot grid, masked to fade before the content.
- `score-glow` — the ambient tint behind the score card and the home input.
  Drawn in `currentColor`, so the element's own band class supplies the hue and
  no new colour value exists. Centred and transparent well before its box edge:
  anchored to the top instead, a clipping parent cut it at full strength and it
  read as a seam.

### Weighting the report

Hierarchy is carried by three things, and none of them is colour alone:

- The score numeral uses `--text-score` (48 → 72px). It is the conclusion of
  the report and should be the largest thing on the page.
- Findings are tiered by severity in `tone.ts` — critical/high get a coloured
  left border on `--color-raised`, medium/low sit flat, pass recedes. The
  `Badge` is identical in every tier, so the weighting is reinforcement; strip
  the colour and the report still reads. `check:contrast` asserts text on both
  new surfaces.
- Section headers carry a rule. They were too quiet to anchor anything.

The report is two columns from 1024px, with the score, its caveats and the
coverage grid sticky at `--spacing-sticky` (which clears the sticky header).
Two things are load-bearing there and both were bugs first: the column needs
`self-start`, because a stretched grid item can never stick, and its children
need `shrink-0`, because flex children default to shrinking and a column with a
`max-height` will compress them instead of scrolling. It also needs the
`max-height` at all — a sticky element taller than the viewport silently stops
sticking. `screenshot-report.mjs layout <domain>` asserts both that it pins and
that its own overflow stays reachable.

---

## 6. Accessibility baseline

Non-negotiable, and cheaper to keep than to retrofit:

- **Contrast.** Every text token clears WCAG AA (4.5:1) against every surface
  it can appear on; focus rings and control boundaries clear 3:1. This is
  enforced, not asserted — `npm run check:contrast` fails the palette if a
  token regresses. Run it after any colour change.
- **Focus is never removed, only styled.** The global `:focus-visible` ring is
  a 2px accent outline with a 2px offset. `outline-color` is pre-set on `*`
  because Tailwind's `transition-colors` includes `outline-color`, and without
  it the ring fades in from `currentColor` instead of appearing instantly.
- **Semantic HTML.** Real `header`/`main`/`footer`, real `<form>` and
  `<label>` — not divs with click handlers. There is a skip link to `#main`.
- **Mobile-first.** 375px is the reference width. No horizontal overflow at
  any width.
- **Motion.** `prefers-reduced-motion: reduce` disables animation globally;
  anything animated must stay legible when it is static. The global rule zeroes
  animation **delay** as well as duration, because a staggered list would
  otherwise still drip its content in — silently, with no motion to explain the
  wait. It cannot reach JavaScript, though: a `requestAnimationFrame` loop
  ignores CSS entirely, so anything animated in JS must check the preference
  itself. `useReducedMotion()` exists for that, and the score count-up uses it.
- Every input needs a label. Use `hideLabel` to hide it visually while keeping
  it announced.

---

## 7. Visual prohibitions

Surfaced is an engineering tool and should look like one. **No stock security
clichés, anywhere:** no shields, no padlocks, no matrix green, no hooded
figures, no binary rain, no glowing red world maps.

The wordmark is pure type — lowercase mono plus a terminal cursor block. Keep
it that way.
