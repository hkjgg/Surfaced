/**
 * Certificate Transparency.
 *
 * CT logs are a public, append-only record of every certificate a CA issues.
 * Reading them tells you which hostnames a domain has published certificates
 * for — which is exactly what an attacker doing reconnaissance would read
 * first, and often the fastest way to find infrastructure someone forgot was
 * public.
 *
 * Nothing here touches the scanned domain. The only request is to crt.sh.
 */

import type { CheckResult, Finding } from "./types";

const CHECK = "ct" as const;

const CRT_SH_ENDPOINT = "https://crt.sh/";

/** crt.sh is frequently slow; this budget is generous but finite. */
const CT_TIMEOUT_MS = 12_000;

/** Guards against an enormous response for a domain with many certificates. */
const MAX_RESPONSE_BYTES = 4_000_000;
const MAX_NAMES_REPORTED = 200;

/**
 * Labels that commonly denote non-production or administrative systems.
 *
 * A name in a CT log is public information by definition, so this is a
 * reconnaissance signal, not a vulnerability: it says "an attacker can find
 * this", not "this is exploitable".
 */
const NOTABLE_LABELS = [
  "dev",
  "staging",
  "stage",
  "test",
  "uat",
  "qa",
  "internal",
  "admin",
  "vpn",
  "jenkins",
  "grafana",
  "jira",
  "kibana",
  "gitlab",
  "sonar",
  "phpmyadmin",
] as const;

interface CrtShEntry {
  readonly name_value?: string;
  readonly common_name?: string;
  readonly not_after?: string;
  readonly issuer_name?: string;
}

export interface CtData {
  readonly totalCertificates: number;
  readonly hostnames: readonly string[];
  readonly hostnameCount: number;
  readonly truncated: boolean;
  readonly notableHostnames: readonly { readonly hostname: string; readonly label: string }[];
}

/**
 * Injected for local verification. Deliberately a parameter rather than an
 * environment variable: CLAUDE.md forbids building a request URL from
 * unvalidated env, and a scanner whose target endpoint can be repointed by
 * configuration is a scanner that can be aimed somewhere it shouldn't be.
 */
export type CtFetcher = (url: string, signal: AbortSignal) => Promise<Response>;

const defaultFetcher: CtFetcher = (url, signal) =>
  fetch(url, {
    signal,
    headers: { accept: "application/json", "user-agent": "Surfaced/1.0" },
    redirect: "error",
  });

function isEntryArray(value: unknown): value is CrtShEntry[] {
  return Array.isArray(value);
}

/**
 * crt.sh returns `name_value` as a newline-delimited list that may contain
 * wildcards and duplicates. Normalise into a deduplicated hostname set.
 */
function extractHostnames(entries: readonly CrtShEntry[], apex: string): Set<string> {
  const names = new Set<string>();
  const suffix = `.${apex}`;

  for (const entry of entries) {
    const raw = `${entry.name_value ?? ""}\n${entry.common_name ?? ""}`;
    for (const line of raw.split("\n")) {
      const name = line.trim().toLowerCase().replace(/^\*\./, "");
      if (!name) continue;
      // Keep only names actually under the scanned domain.
      if (name !== apex && !name.endsWith(suffix)) continue;
      names.add(name);
    }
  }

  return names;
}

function findNotable(
  hostnames: Iterable<string>,
  apex: string,
): { hostname: string; label: string }[] {
  const notable: { hostname: string; label: string }[] = [];

  for (const hostname of hostnames) {
    if (hostname === apex) continue;
    const labels = hostname.slice(0, -apex.length - 1).split(".");

    for (const marker of NOTABLE_LABELS) {
      // Match whole labels, so "development" matches but "devon.example.com"
      // does not become a false positive on a substring.
      if (labels.some((label) => label === marker || label.startsWith(`${marker}-`))) {
        notable.push({ hostname, label: marker });
        break;
      }
    }
  }

  return notable;
}

export async function checkCt(
  hostname: string,
  signal: AbortSignal,
  fetcher: CtFetcher = defaultFetcher,
): Promise<CheckResult<CtData>> {
  const started = Date.now();
  signal.throwIfAborted();

  const url = new URL(CRT_SH_ENDPOINT);
  url.searchParams.set("q", `%.${hostname}`);
  url.searchParams.set("output", "json");
  url.searchParams.set("exclude", "expired");

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), CT_TIMEOUT_MS);
  const onParentAbort = () => controller.abort();
  signal.addEventListener("abort", onParentAbort, { once: true });

  let entries: CrtShEntry[];
  try {
    const response = await fetcher(url.href, controller.signal);

    if (!response.ok) {
      throw new Error(`crt.sh returned HTTP ${response.status}`);
    }

    const declaredLength = Number.parseInt(
      response.headers.get("content-length") ?? "",
      10,
    );
    if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
      throw new Error(
        `crt.sh response is ${declaredLength} bytes, over the ${MAX_RESPONSE_BYTES} byte cap`,
      );
    }

    const text = await response.text();
    if (text.length > MAX_RESPONSE_BYTES) {
      throw new Error(`crt.sh response exceeded the ${MAX_RESPONSE_BYTES} byte cap`);
    }

    const parsed: unknown = JSON.parse(text);
    if (!isEntryArray(parsed)) {
      throw new Error("crt.sh returned an unexpected payload shape");
    }
    entries = parsed;
  } finally {
    clearTimeout(timer);
    signal.removeEventListener("abort", onParentAbort);
  }

  const allNames = extractHostnames(entries, hostname);
  const sorted = [...allNames].sort();
  const truncated = sorted.length > MAX_NAMES_REPORTED;
  const hostnames = sorted.slice(0, MAX_NAMES_REPORTED);
  const notableHostnames = findNotable(sorted, hostname);

  const findings: Finding[] = [];

  if (notableHostnames.length > 0) {
    const sample = notableHostnames.slice(0, 12).map((entry) => entry.hostname);

    findings.push({
      id: "ct.notable-hostnames",
      check: CHECK,
      severity: "low",
      title: `${notableHostnames.length} certificate name${
        notableHostnames.length === 1 ? "" : "s"
      } suggest non-production systems`,
      observed: `Certificate Transparency logs list ${sample.join(", ")}${
        notableHostnames.length > sample.length
          ? ` and ${notableHostnames.length - sample.length} more`
          : ""
      }.`,
      impact:
        "These names are already public — CT logs are published by design, and this check only reads them. The risk is not disclosure but attention: names like these tell an attacker where to look for staging systems that are often less hardened than production.",
      remediation: {
        summary:
          "Confirm each of these is meant to be internet-facing. For those that are not, put them behind a VPN or an identity-aware proxy. If you need certificates without publishing names, use a wildcard certificate.",
      },
    });
  } else if (sorted.length > 0) {
    findings.push({
      id: "ct.no-notable-hostnames",
      check: CHECK,
      severity: "pass",
      title: "No obviously non-production hostnames in CT logs",
      observed: `${sorted.length} hostname${sorted.length === 1 ? "" : "s"} found across ${entries.length} logged certificate${entries.length === 1 ? "" : "s"}; none matched the non-production patterns checked.`,
      impact:
        "Nothing in the public certificate record points at staging or admin systems by name. This is a heuristic on naming, not proof that none exist.",
    });
  } else {
    findings.push({
      id: "ct.no-certificates",
      check: CHECK,
      severity: "low",
      title: "No unexpired certificates found in CT logs",
      observed: `crt.sh returned no current certificates for ${hostname}.`,
      impact:
        "This is unusual for a live site. It may mean the domain does not serve HTTPS, or that crt.sh has not indexed its certificates.",
    });
  }

  return {
    check: CHECK,
    status: "ok",
    findings,
    data: {
      totalCertificates: entries.length,
      hostnames,
      hostnameCount: sorted.length,
      truncated,
      notableHostnames,
    },
    durationMs: Date.now() - started,
  };
}
