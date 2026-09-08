/**
 * SPF, DKIM and DMARC — the three records that decide whether someone can
 * send mail as this domain.
 *
 * All three are ordinary public TXT lookups. Nothing is sent to the domain's
 * mail servers.
 */

import { getDomain } from "tldts";

import type { CheckResult, Finding } from "./types";
import { resolveTxt } from "./internal/resolver";

const CHECK = "email-auth" as const;

/**
 * DKIM selectors are chosen by whoever set up signing and are NOT enumerable
 * from DNS — there is no record that lists them. This list covers common
 * provider defaults, so finding one is evidence DKIM exists, but finding none
 * proves nothing at all.
 *
 * Consequently this check never reports "DKIM is missing". Doing so would be
 * the exact failure mode that makes a scanner worse than useless: a confident,
 * plausible, wrong answer.
 */
const DKIM_SELECTORS = [
  "default",
  "google",
  "selector1",
  "selector2",
  "k1",
  "mail",
  "dkim",
  "s1",
  "s2",
] as const;

/** RFC 7208 §4.6.4: at most 10 DNS-querying mechanisms during evaluation. */
const SPF_LOOKUP_LIMIT = 10;

/** Mechanisms that cost a DNS lookup. ip4, ip6 and all do not. */
const LOOKUP_MECHANISMS = new Set(["include", "a", "mx", "ptr", "exists"]);

type Qualifier = "+" | "-" | "~" | "?";

export interface SpfTerm {
  readonly qualifier: Qualifier;
  readonly mechanism: string;
  readonly value: string | null;
  readonly costsLookup: boolean;
}

export interface SpfAnalysis {
  readonly present: boolean;
  readonly record: string | null;
  /** More than one SPF record is itself an RFC 7208 violation. */
  readonly duplicateRecords: number;
  readonly terms: readonly SpfTerm[];
  /** The qualifier on `all`, or null when the record has no `all`. */
  readonly allQualifier: Qualifier | null;
  readonly lookupCount: number;
  /**
   * False when recursion into include/redirect could not finish. The count is
   * then a lower bound and must not be presented as authoritative.
   */
  readonly lookupCountComplete: boolean;
  readonly includeChain: readonly string[];
}

export interface DkimAnalysis {
  /** Selectors publishing a usable public key. */
  readonly selectorsFound: readonly string[];
  /**
   * Selectors publishing a record whose p= tag is empty. RFC 6376 §3.6.1 is
   * explicit that an empty p= means the key has been REVOKED — it is not a
   * working key, and reporting it as one would be plainly wrong. Domains that
   * send no mail sometimes publish these deliberately.
   */
  readonly selectorsRevoked: readonly string[];
  readonly selectorsProbed: readonly string[];
  /** Always true. Kept explicit so consumers cannot forget it. */
  readonly listNotExhaustive: true;
}

export interface DmarcAnalysis {
  readonly present: boolean;
  readonly record: string | null;
  /**
   * When the scanned name is a subdomain with no record of its own, DMARC
   * falls back to the organizational domain's policy (RFC 7489 §6.6.3) — with
   * its sp= tag taking precedence over p= for subdomains. Reporting "no
   * DMARC" without checking that fallback would be wrong.
   */
  readonly inheritedFrom: string | null;
  readonly policy: string | null;
  readonly subdomainPolicy: string | null;
  readonly percent: number;
  readonly rua: readonly string[];
  readonly ruf: readonly string[];
}

export interface EmailAuthData {
  readonly spf: SpfAnalysis;
  readonly dkim: DkimAnalysis;
  readonly dmarc: DmarcAnalysis;
}

function isQualifier(value: string): value is Qualifier {
  return value === "+" || value === "-" || value === "~" || value === "?";
}

/** Parse one SPF record into its terms. Does not perform any DNS lookups. */
export function parseSpfRecord(record: string): {
  terms: SpfTerm[];
  allQualifier: Qualifier | null;
} {
  const terms: SpfTerm[] = [];
  let allQualifier: Qualifier | null = null;

  // Drop the version token, then split on runs of whitespace.
  const tokens = record.trim().split(/\s+/).slice(1);

  for (const token of tokens) {
    if (!token) continue;

    const first = token[0] ?? "";
    const hasQualifier = isQualifier(first);
    const qualifier: Qualifier = hasQualifier ? first : "+";
    const body = hasQualifier ? token.slice(1) : token;

    const separator = body.search(/[:=]/);
    const mechanism = (
      separator === -1 ? body : body.slice(0, separator)
    ).toLowerCase();
    const value = separator === -1 ? null : body.slice(separator + 1);

    if (mechanism === "all") allQualifier = qualifier;

    terms.push({
      qualifier,
      mechanism,
      value,
      // `redirect=` is a modifier rather than a mechanism but still costs a
      // lookup, so it is counted here alongside the mechanisms.
      costsLookup: LOOKUP_MECHANISMS.has(mechanism) || mechanism === "redirect",
    });
  }

  return { terms, allQualifier };
}

function findSpfRecords(records: readonly string[]): string[] {
  return records.filter((record) => /^v=spf1(\s|$)/i.test(record.trim()));
}

/**
 * Count DNS-querying terms across the whole evaluation, following include and
 * redirect.
 *
 * The RFC limit applies to a full evaluation, not to one record, so a domain
 * can be over the limit without any single record looking suspicious. The
 * visited set prevents include loops; the budget stops a pathological chain
 * from consuming the check's whole time allowance.
 */
async function countSpfLookups(
  domain: string,
  rootTerms: readonly SpfTerm[],
): Promise<{ count: number; complete: boolean; chain: string[] }> {
  const visited = new Set<string>([domain.toLowerCase()]);
  const chain: string[] = [];
  let count = 0;
  let complete = true;

  // Bounded work: enough to catch real misconfiguration, not enough to let a
  // hostile record turn the scanner into a DNS amplifier.
  const MAX_RESOLUTIONS = 25;
  let resolutions = 0;

  const walk = async (terms: readonly SpfTerm[], depth: number): Promise<void> => {
    for (const term of terms) {
      if (!term.costsLookup) continue;
      count += 1;

      const isRecursive = term.mechanism === "include" || term.mechanism === "redirect";
      if (!isRecursive || !term.value) continue;

      const target = term.value.toLowerCase();
      if (visited.has(target)) continue;
      visited.add(target);
      chain.push(target);

      // Once over the limit the exact total no longer changes the finding,
      // and depth is capped regardless.
      if (count > SPF_LOOKUP_LIMIT || depth >= 5 || resolutions >= MAX_RESOLUTIONS) {
        complete = false;
        continue;
      }

      resolutions += 1;
      try {
        const nested = findSpfRecords(await resolveTxt(target, 3_000));
        const first = nested[0];
        if (first) await walk(parseSpfRecord(first).terms, depth + 1);
      } catch {
        // An include pointing at a name that will not resolve is itself a
        // fault, but we cannot count what we cannot read.
        complete = false;
      }
    }
  };

  await walk(rootTerms, 0);
  return { count, complete, chain };
}

function parseDmarcRecord(
  record: string,
): Omit<DmarcAnalysis, "present" | "record" | "inheritedFrom"> {
  const tags = new Map<string, string>();

  for (const part of record.split(";")) {
    const [rawKey, ...rest] = part.split("=");
    const key = rawKey?.trim().toLowerCase();
    if (!key || rest.length === 0) continue;
    tags.set(key, rest.join("=").trim());
  }

  const parsedPercent = Number.parseInt(tags.get("pct") ?? "100", 10);

  const addresses = (tag: string): string[] =>
    (tags.get(tag) ?? "")
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);

  return {
    policy: tags.get("p")?.toLowerCase() ?? null,
    subdomainPolicy: tags.get("sp")?.toLowerCase() ?? null,
    // An out-of-range or unparseable pct is treated as the RFC default.
    percent:
      Number.isFinite(parsedPercent) && parsedPercent >= 0 && parsedPercent <= 100
        ? parsedPercent
        : 100,
    rua: addresses("rua"),
    ruf: addresses("ruf"),
  };
}

function suggestedDmarc(domain: string): string {
  return `v=DMARC1; p=reject; rua=mailto:dmarc-reports@${domain}; fo=1`;
}

export async function checkEmailAuth(
  hostname: string,
  signal: AbortSignal,
): Promise<CheckResult<EmailAuthData>> {
  const started = Date.now();
  signal.throwIfAborted();

  const organizationalDomain = getDomain(hostname);
  const isSubdomain =
    organizationalDomain !== null && organizationalDomain !== hostname;

  const [apexTxt, dmarcTxt, dkimResults] = await Promise.all([
    resolveTxt(hostname),
    resolveTxt(`_dmarc.${hostname}`).catch(() => [] as string[]),
    Promise.all(
      DKIM_SELECTORS.map(async (selector) => {
        try {
          const records = await resolveTxt(`${selector}._domainkey.${hostname}`, 3_000);
          const record = records.find((candidate) =>
            /(^|;)\s*(v=DKIM1|k=|p=)/i.test(candidate),
          );
          if (!record) return null;

          // p= is the public key. Present-but-empty means revoked.
          const publicKey = record.match(/(?:^|;)\s*p\s*=\s*([^;]*)/i)?.[1]?.trim() ?? "";
          return { selector, revoked: publicKey.length === 0 };
        } catch {
          return null;
        }
      }),
    ),
  ]);

  const findings: Finding[] = [];

  // ---- SPF ----------------------------------------------------------------
  const spfRecords = findSpfRecords(apexTxt);
  const primarySpf = spfRecords[0] ?? null;
  const parsed = primarySpf
    ? parseSpfRecord(primarySpf)
    : { terms: [] as SpfTerm[], allQualifier: null };

  const lookups = primarySpf
    ? await countSpfLookups(hostname, parsed.terms)
    : { count: 0, complete: true, chain: [] as string[] };

  const spf: SpfAnalysis = {
    present: spfRecords.length > 0,
    record: primarySpf,
    duplicateRecords: spfRecords.length,
    terms: parsed.terms,
    allQualifier: parsed.allQualifier,
    lookupCount: lookups.count,
    lookupCountComplete: lookups.complete,
    includeChain: lookups.chain,
  };

  if (!spf.present) {
    findings.push({
      id: "spf.missing",
      check: CHECK,
      severity: "high",
      title: "No SPF record",
      observed: `${hostname} publishes no TXT record beginning with v=spf1.`,
      impact:
        "Receiving mail servers have no list of hosts allowed to send as this domain, so forged mail is harder for them to reject.",
      remediation: {
        summary: "Publish an SPF record listing every host that sends your mail, ending in -all.",
        dnsRecord: { name: hostname, type: "TXT", value: "v=spf1 -all" },
        reference: "RFC 7208",
      },
    });
  } else {
    if (spf.duplicateRecords > 1) {
      findings.push({
        id: "spf.duplicate",
        check: CHECK,
        severity: "high",
        title: "More than one SPF record",
        observed: `${hostname} publishes ${spf.duplicateRecords} records starting with v=spf1.`,
        impact:
          "RFC 7208 requires exactly one. Receivers treat multiple records as a permanent error and SPF stops being evaluated at all.",
        remediation: {
          summary: "Merge the records into a single TXT record and delete the others.",
          dnsRecord: { name: hostname, type: "TXT", value: "v=spf1 -all" },
          reference: "RFC 7208 §3.2",
        },
      });
    }

    if (spf.allQualifier === "+") {
      findings.push({
        id: "spf.all.pass",
        check: CHECK,
        severity: "critical",
        title: "SPF ends in +all",
        observed: `The SPF record is "${spf.record}", which ends in +all.`,
        impact:
          "+all tells every receiver that any host on the internet is authorised to send mail as this domain. It is worse than having no SPF record, because it actively vouches for forgeries.",
        remediation: {
          summary: "Replace +all with -all so only listed hosts are authorised.",
          dnsRecord: {
            name: hostname,
            type: "TXT",
            value: `${spf.record?.replace(/\+all/i, "-all") ?? "v=spf1 -all"}`,
          },
          reference: "RFC 7208 §5.1",
        },
      });
    } else if (spf.allQualifier === "?") {
      findings.push({
        id: "spf.all.neutral",
        check: CHECK,
        severity: "medium",
        title: "SPF ends in ?all",
        observed: `The SPF record ends in ?all (neutral).`,
        impact:
          "A neutral result tells receivers nothing, so unauthorised senders are treated no differently from authorised ones.",
        remediation: {
          summary: "Move to ~all while you monitor, then to -all.",
          dnsRecord: {
            name: hostname,
            type: "TXT",
            value: `${spf.record?.replace(/\?all/i, "-all") ?? "v=spf1 -all"}`,
          },
          reference: "RFC 7208 §5.1",
        },
      });
    } else if (spf.allQualifier === null) {
      findings.push({
        id: "spf.all.absent",
        check: CHECK,
        severity: "medium",
        title: "SPF record has no all mechanism",
        observed: `The SPF record is "${spf.record}", with no all term.`,
        impact:
          "Without a final all mechanism the default result is neutral, so senders not otherwise matched are not rejected.",
        remediation: {
          summary: "Append -all to the end of the record.",
          dnsRecord: { name: hostname, type: "TXT", value: `${spf.record} -all` },
          reference: "RFC 7208 §5.1",
        },
      });
    } else if (spf.allQualifier === "~") {
      findings.push({
        id: "spf.all.softfail",
        check: CHECK,
        severity: "low",
        title: "SPF ends in ~all (softfail)",
        observed: `The SPF record ends in ~all.`,
        impact:
          "Softfail asks receivers to accept but mark unauthorised mail. It is a reasonable staging step, but it does not stop forgery.",
        remediation: {
          summary: "Once you are confident every sender is listed, move to -all.",
          dnsRecord: {
            name: hostname,
            type: "TXT",
            value: `${spf.record?.replace(/~all/i, "-all") ?? "v=spf1 -all"}`,
          },
          reference: "RFC 7208 §5.1",
        },
      });
    } else {
      findings.push({
        id: "spf.all.fail",
        check: CHECK,
        severity: "pass",
        title: "SPF ends in -all",
        observed: `The SPF record is "${spf.record}".`,
        impact: "Receivers are told to reject mail from any host not listed.",
      });
    }

    if (spf.lookupCount > SPF_LOOKUP_LIMIT) {
      findings.push({
        id: "spf.lookup-limit",
        check: CHECK,
        severity: "high",
        title: "SPF exceeds the 10 DNS-lookup limit",
        observed: `Evaluating this record requires ${spf.lookupCount} DNS lookups${
          spf.lookupCountComplete ? "" : " (at least — the chain could not be fully followed)"
        }, against a limit of ${SPF_LOOKUP_LIMIT}.`,
        impact:
          "RFC 7208 requires receivers to return permerror past 10 lookups. Once that happens SPF fails for all your mail, including legitimate mail.",
        remediation: {
          summary:
            "Reduce the include chain — flatten includes into ip4/ip6 ranges, or drop senders you no longer use.",
          reference: "RFC 7208 §4.6.4",
        },
      });
    } else if (!spf.lookupCountComplete) {
      findings.push({
        id: "spf.lookup-incomplete",
        check: CHECK,
        severity: "low",
        title: "SPF lookup count could not be fully resolved",
        observed: `At least ${spf.lookupCount} of the ${SPF_LOOKUP_LIMIT} permitted DNS lookups are used, but part of the include chain could not be followed.`,
        impact:
          "The record may still be within the limit. This is reported as incomplete rather than guessed, because a wrong count here would be worse than none.",
      });
    }
  }

  // ---- DKIM ---------------------------------------------------------------
  interface DkimProbe {
    readonly selector: string;
    readonly revoked: boolean;
  }
  const dkimSelectors: DkimProbe[] = dkimResults.filter(
    (value): value is NonNullable<typeof value> => value !== null,
  );
  const selectorsFound = dkimSelectors
    .filter((entry) => !entry.revoked)
    .map((entry) => entry.selector);
  const selectorsRevoked = dkimSelectors
    .filter((entry) => entry.revoked)
    .map((entry) => entry.selector);

  const dkim: DkimAnalysis = {
    selectorsFound,
    selectorsRevoked,
    selectorsProbed: [...DKIM_SELECTORS],
    listNotExhaustive: true,
  };

  if (selectorsFound.length === 0 && selectorsRevoked.length > 0) {
    // Publishing an explicitly revoked key is a deliberate act. Combined with
    // a null MX and -all SPF it is a coherent "this domain sends no mail"
    // posture, so it is reported for what it is rather than as a fault.
    findings.push({
      id: "dkim.revoked",
      check: CHECK,
      severity: "low",
      title: "DKIM records are published but the keys are revoked",
      observed: `${selectorsRevoked
        .map((selector) => `${selector}._domainkey.${hostname}`)
        .join(", ")} publish a DKIM record with an empty p= tag.`,
      impact:
        "An empty p= revokes the key (RFC 6376 §3.6.1), so no signature made with it can verify. For a domain that deliberately sends no mail this is a correct, intentional posture; for one that does send mail it means DKIM is broken at these selectors.",
      remediation: {
        summary:
          "If this domain sends mail, publish the real public key at these selectors. If it does not, this is already correct.",
        reference: "RFC 6376 §3.6.1",
      },
    });
  } else {
  findings.push(
    selectorsFound.length > 0
      ? {
          id: "dkim.found",
          check: CHECK,
          severity: "pass",
          title: "DKIM signing key published",
          observed: `Found DKIM keys at ${selectorsFound
            .map((selector) => `${selector}._domainkey.${hostname}`)
            .join(", ")}.`,
          impact:
            "At least one DKIM key is published. Note that selectors cannot be enumerated from DNS, so this domain may publish others.",
        }
      : {
          id: "dkim.none-of-probed",
          check: CHECK,
          severity: "low",
          title: "No DKIM key found at the selectors checked",
          observed: `Checked ${DKIM_SELECTORS.length} common selectors (${DKIM_SELECTORS.join(", ")}) and none returned a key.`,
          impact:
            "This is not evidence that DKIM is missing. Selectors are chosen freely and cannot be enumerated from DNS, so a domain using a custom selector will look identical to one with no DKIM at all. Confirm with whoever runs your mail.",
          remediation: {
            summary:
              "If you do not already sign outbound mail with DKIM, enable it with your mail provider and publish the key they give you.",
            reference: "RFC 6376",
          },
        },
  );
  }

  // ---- DMARC --------------------------------------------------------------
  const isDmarc = (record: string) => /^v=DMARC1\s*;/i.test(record.trim());

  let dmarcRecords = dmarcTxt.filter(isDmarc);
  let inheritedFrom: string | null = null;

  // No record of its own and this is a subdomain: check the organizational
  // domain before concluding anything. Receivers do exactly this.
  if (dmarcRecords.length === 0 && isSubdomain && organizationalDomain) {
    try {
      const parentRecords = (
        await resolveTxt(`_dmarc.${organizationalDomain}`, 3_000)
      ).filter(isDmarc);
      if (parentRecords.length > 0) {
        dmarcRecords = parentRecords;
        inheritedFrom = organizationalDomain;
      }
    } catch {
      // Leave it absent rather than guessing.
    }
  }

  const primaryDmarc = dmarcRecords[0] ?? null;
  const dmarcTags = primaryDmarc
    ? parseDmarcRecord(primaryDmarc)
    : {
        policy: null,
        subdomainPolicy: null,
        percent: 100,
        rua: [] as string[],
        ruf: [] as string[],
      };

  const dmarc: DmarcAnalysis = {
    present: primaryDmarc !== null,
    record: primaryDmarc,
    inheritedFrom,
    ...dmarcTags,
  };

  // For an inherited policy the subdomain policy tag governs, falling back to
  // p= when sp= is absent.
  const effectivePolicy = inheritedFrom
    ? (dmarc.subdomainPolicy ?? dmarc.policy)
    : dmarc.policy;

  if (!dmarc.present) {
    findings.push({
      id: "dmarc.missing",
      check: CHECK,
      severity: "high",
      title: "No DMARC record",
      observed: isSubdomain && organizationalDomain
        ? `Neither _dmarc.${hostname} nor _dmarc.${organizationalDomain} publishes a DMARC record.`
        : `_dmarc.${hostname} publishes no DMARC record.`,
      impact:
        "Without DMARC, SPF and DKIM results are advisory only. Receivers have no instruction about what to do with mail that fails them, and you get no reports about who is sending as you.",
      remediation: {
        summary:
          "Publish a DMARC record. Start at p=none to collect reports, then tighten to quarantine and reject.",
        dnsRecord: {
          name: `_dmarc.${hostname}`,
          type: "TXT",
          value: suggestedDmarc(hostname),
        },
        reference: "RFC 7489",
      },
    });
  } else {
    if (effectivePolicy === "none") {
      findings.push({
        id: "dmarc.policy.none",
        check: CHECK,
        severity: "medium",
        title: "DMARC policy is p=none",
        observed: `The DMARC record is "${dmarc.record}".`,
        impact:
          "p=none is monitor-only. Receivers report what they saw but still deliver mail that fails authentication, so forgery is observed rather than stopped.",
        remediation: {
          summary:
            "Once your reports show all legitimate mail passing, move to p=quarantine and then p=reject.",
          dnsRecord: {
            name: `_dmarc.${hostname}`,
            type: "TXT",
            value: dmarc.record?.replace(/p=none/i, "p=quarantine") ?? suggestedDmarc(hostname),
          },
          reference: "RFC 7489 §6.3",
        },
      });
    } else if (effectivePolicy === "quarantine" || effectivePolicy === "reject") {
      findings.push({
        id: "dmarc.policy.enforcing",
        check: CHECK,
        severity: "pass",
        title: `DMARC policy is ${effectivePolicy}`,
        observed: inheritedFrom
          ? `${hostname} publishes no DMARC record of its own, so it inherits the policy from ${inheritedFrom}: "${dmarc.record}" (sp=${dmarc.subdomainPolicy ?? "absent, so p= applies"}).`
          : `The DMARC record is "${dmarc.record}".`,
        impact:
          effectivePolicy === "reject"
            ? "Receivers are told to reject mail that fails authentication."
            : "Receivers are told to quarantine mail that fails authentication.",
      });
    } else {
      findings.push({
        id: "dmarc.policy.invalid",
        check: CHECK,
        severity: "medium",
        title: "DMARC record has no usable policy",
        observed: `The DMARC record is "${dmarc.record}", with an effective policy of ${effectivePolicy ?? "(absent)"}.`,
        impact:
          "A DMARC record without a valid p= tag is ignored by receivers, so it provides neither enforcement nor reporting.",
        remediation: {
          summary: "Add a valid policy tag.",
          dnsRecord: {
            name: `_dmarc.${hostname}`,
            type: "TXT",
            value: suggestedDmarc(hostname),
          },
          reference: "RFC 7489 §6.3",
        },
      });
    }

    if (dmarc.percent < 100) {
      findings.push({
        id: "dmarc.pct",
        check: CHECK,
        severity: "low",
        title: `DMARC applies to only ${dmarc.percent}% of mail`,
        observed: `The record sets pct=${dmarc.percent}.`,
        impact: `The policy is applied to ${dmarc.percent}% of failing messages; the rest are treated as if the policy were weaker.`,
        remediation: {
          summary: "Raise pct to 100 once you are confident in the policy.",
          dnsRecord: {
            name: `_dmarc.${hostname}`,
            type: "TXT",
            value: dmarc.record?.replace(/pct=\d+/i, "pct=100") ?? suggestedDmarc(hostname),
          },
          reference: "RFC 7489 §6.3",
        },
      });
    }

    if (dmarc.rua.length === 0) {
      findings.push({
        id: "dmarc.no-rua",
        check: CHECK,
        severity: "low",
        title: "DMARC has no aggregate report address",
        observed: "The DMARC record has no rua= tag.",
        impact:
          "Without rua you receive no aggregate reports, so you cannot tell whether the policy is blocking forgery or breaking your own mail.",
        remediation: {
          summary: "Add an rua address to start receiving aggregate reports.",
          dnsRecord: {
            name: `_dmarc.${hostname}`,
            type: "TXT",
            value: `${dmarc.record}${dmarc.record?.trimEnd().endsWith(";") ? "" : ";"} rua=mailto:dmarc-reports@${hostname}`,
          },
          reference: "RFC 7489 §6.3",
        },
      });
    }
  }

  return {
    check: CHECK,
    status: "ok",
    findings,
    data: { spf, dkim, dmarc },
    durationMs: Date.now() - started,
  };
}
