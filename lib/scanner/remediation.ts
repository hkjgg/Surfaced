/**
 * Turning a `Remediation` into copy-ready deployment forms.
 *
 * Pure and I/O-free: it only reshapes values the checks already produced. That
 * matters, because the no-placeholder rule applies with full force here. A
 * config snippet is the one thing in the report a reader will paste straight
 * into production without editing, so every byte it emits has to be literally
 * correct for the domain that was scanned.
 *
 * Where a fix cannot be expressed faithfully as a snippet, this module returns
 * FEWER targets rather than a plausible-looking wrong one. See
 * `parseHeaderLine`.
 */

import type { Remediation } from "./types";

export type RemediationTargetId =
  | "dns"
  | "header"
  | "nginx"
  | "apache"
  | "cloudflare"
  | "vercel";

export interface RemediationTarget {
  readonly id: RemediationTargetId;
  /** Tab label. */
  readonly label: string;
  /** The exact text a copy button puts on the clipboard. */
  readonly code: string;
  /** Where this goes, shown under the snippet. */
  readonly note: string;
}

/** Longest string a single TXT character-string may hold (RFC 1035 §3.3.14). */
const TXT_CHUNK = 255;

/**
 * Split a TXT value into quoted character-strings.
 *
 * A DKIM key or a long SPF record exceeds 255 bytes, and a zone file line that
 * ignores that is simply invalid. Most providers do this splitting for you in
 * their UI, but the zone-file form we hand out has to be correct on its own.
 */
function quoteTxt(value: string): string {
  if (value.length <= TXT_CHUNK) return JSON.stringify(value);

  const chunks: string[] = [];
  for (let index = 0; index < value.length; index += TXT_CHUNK) {
    chunks.push(JSON.stringify(value.slice(index, index + TXT_CHUNK)));
  }
  return chunks.join(" ");
}

/**
 * Split "Name: value" into its two halves — or return null when the line is
 * not a literal header.
 *
 * Some remediations carry an instruction in the header slot rather than a
 * value to send: `X-Powered-By: (remove this header)` asks for a header to be
 * DELETED, and `Location: https://example.com/` describes a redirect, not a
 * header to add to every response. Emitting `add_header X-Powered-By "(remove
 * this header)"` would be actively harmful — it would add the very header the
 * finding asked you to remove, with a parenthetical as its value.
 *
 * So those lines produce no deployment targets at all. The finding still shows
 * its summary; it just does not pretend there is a snippet to paste.
 */
function parseHeaderLine(
  line: string,
): { readonly name: string; readonly value: string } | null {
  const separator = line.indexOf(":");
  if (separator <= 0) return null;

  const name = line.slice(0, separator).trim();
  const value = line.slice(separator + 1).trim();

  if (name.length === 0 || value.length === 0) return null;

  // A parenthetical is prose for a human, not a header value.
  if (value.startsWith("(")) return null;

  // Location is per-response, set by a redirect rule. There is no correct way
  // to express it as a blanket response header, so we do not try.
  if (name.toLowerCase() === "location") return null;

  return { name, value };
}

/** Escape for a double-quoted nginx / Apache directive argument. */
function quoteDirective(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function headerTargets(name: string, value: string): RemediationTarget[] {
  const vercelConfig = {
    headers: [
      {
        source: "/(.*)",
        headers: [{ key: name, value }],
      },
    ],
  };

  return [
    {
      id: "header",
      label: "Header",
      code: `${name}: ${value}`,
      note: "The response header itself, as it should appear on the wire.",
    },
    {
      id: "nginx",
      label: "Nginx",
      code: `add_header ${name} ${quoteDirective(value)} always;`,
      note: "In the server or location block. `always` sends it on error responses too.",
    },
    {
      id: "apache",
      label: "Apache",
      code: `Header always set ${name} ${quoteDirective(value)}`,
      note: "In the vhost or .htaccess, with mod_headers enabled.",
    },
    {
      id: "cloudflare",
      label: "Cloudflare",
      code: `# _headers — Cloudflare Pages\n/*\n  ${name}: ${value}`,
      note: "For a proxied origin instead: Rules → Transform Rules → Modify Response Header → Set static.",
    },
    {
      id: "vercel",
      label: "vercel.json",
      code: JSON.stringify(vercelConfig, null, 2),
      note: "Merge into the existing `headers` array if the project already has one.",
    },
  ];
}

function dnsTarget(record: NonNullable<Remediation["dnsRecord"]>): RemediationTarget {
  const value =
    record.type === "TXT" ? quoteTxt(record.value) : record.value;

  return {
    id: "dns",
    label: "DNS record",
    code: `${record.name}. IN ${record.type} ${value}`,
    note: `Most providers ask for the three fields separately: name ${record.name}, type ${record.type}, value below.`,
  };
}

/**
 * Every deployment form for one remediation, in tab order.
 *
 * An empty array is a legitimate answer: plenty of fixes ("renew the
 * certificate", "add a second nameserver") are actions rather than
 * configuration, and inventing a snippet for them would be worse than none.
 */
export function remediationTargets(
  remediation: Remediation | undefined,
): RemediationTarget[] {
  if (!remediation) return [];

  const targets: RemediationTarget[] = [];

  if (remediation.dnsRecord) {
    targets.push(dnsTarget(remediation.dnsRecord));
  }

  if (remediation.headerLine) {
    const parsed = parseHeaderLine(remediation.headerLine);
    if (parsed) targets.push(...headerTargets(parsed.name, parsed.value));
  }

  return targets;
}
