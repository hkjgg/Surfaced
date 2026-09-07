/**
 * Certificate posture.
 *
 * A standard TLS handshake on 443 — the same one a browser performs — read
 * for what the server presented. No cipher enumeration, no downgrade attempts,
 * no renegotiation games: one connection, one certificate, then close.
 */

import tls, { type PeerCertificate } from "node:tls";

import type { CheckResult, Finding } from "./types";
import { readSignatureAlgorithm } from "./internal/certificate";

const CHECK = "tls" as const;

const HANDSHAKE_TIMEOUT_MS = 8_000;
const EXPIRY_WARNING_DAYS = 30;
const MIN_RSA_KEY_BITS = 2048;

/**
 * Chain-verification errors that another finding already reports in more
 * specific terms. Emitting "the chain did not verify" next to "the
 * certificate expired" describes one fault twice, and score.ts would deduct
 * for it twice.
 */
const EXPLAINED_ELSEWHERE = new Set([
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "ERR_TLS_CERT_ALTNAME_INVALID",
]);

export interface TlsData {
  readonly protocol: string | null;
  readonly cipher: string | null;
  readonly subject: string | null;
  readonly issuer: string | null;
  readonly subjectAltNames: readonly string[];
  readonly validFrom: string | null;
  readonly validTo: string | null;
  readonly daysUntilExpiry: number | null;
  readonly keyBits: number | null;
  readonly signatureAlgorithm: string | null;
  readonly selfSigned: boolean;
  readonly hostnameMatches: boolean;
  /** Node's own chain verdict, e.g. CERT_HAS_EXPIRED. null when it verified. */
  readonly authorizationError: string | null;
}

interface Handshake {
  readonly certificate: PeerCertificate;
  readonly protocol: string | null;
  readonly cipher: string | null;
  readonly authorized: boolean;
  readonly authorizationError: string | null;
}

/**
 * Open one TLS connection and capture what the peer presented.
 *
 * `rejectUnauthorized: false` is required and is not a weakening of anything:
 * with verification on, Node throws before the certificate can be inspected,
 * so the scanner could never report "this certificate is expired" — precisely
 * the finding users most need. Nothing here trusts the certificate; the chain
 * verdict is captured in `authorizationError` and adjudicated below.
 */
function handshake(hostname: string, signal: AbortSignal): Promise<Handshake> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      rejectUnauthorized: false,
      timeout: HANDSHAKE_TIMEOUT_MS,
      // Node's client floor is TLS 1.2. Left at the default, a server that
      // only speaks TLS 1.0/1.1 fails the handshake and gets reported as
      // "connection error" — the one thing it definitely is not. Lowering the
      // floor lets the scanner observe and name the real problem. Nothing
      // confidential is sent over this socket; it is a handshake and a close.
      minVersion: "TLSv1",
      // SECLEVEL=0 is needed for the same reason: OpenSSL 3 otherwise refuses
      // the older cipher suites such a server offers, before we can see it.
      ciphers: "DEFAULT@SECLEVEL=0",
    });

    const cleanup = () => {
      signal.removeEventListener("abort", onAbort);
      socket.removeAllListeners();
      socket.destroy();
    };

    function onAbort() {
      cleanup();
      reject(new Error("TLS check aborted"));
    }

    signal.addEventListener("abort", onAbort, { once: true });

    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate(true);
      const result: Handshake = {
        certificate,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name ?? null,
        authorized: socket.authorized,
        authorizationError: socket.authorized
          ? null
          : (socket.authorizationError?.message ??
            String(socket.authorizationError ?? "unknown")),
      };
      cleanup();
      resolve(result);
    });

    socket.once("timeout", () => {
      cleanup();
      reject(new Error(`TLS handshake timed out after ${HANDSHAKE_TIMEOUT_MS}ms`));
    });

    socket.once("error", (error: Error) => {
      cleanup();
      reject(error);
    });
  });
}

/** Subject Alternative Names, as a plain list of DNS entries. */
function parseSans(certificate: PeerCertificate): string[] {
  if (!certificate.subjectaltname) return [];
  return certificate.subjectaltname
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.toLowerCase().startsWith("dns:"))
    .map((entry) => entry.slice(4).toLowerCase());
}

/** RFC 6125 wildcard matching: *.example.com matches one label only. */
function sanMatches(hostname: string, san: string): boolean {
  if (san === hostname) return true;
  if (!san.startsWith("*.")) return false;

  const suffix = san.slice(1); // ".example.com"
  if (!hostname.endsWith(suffix)) return false;

  const prefix = hostname.slice(0, hostname.length - suffix.length);
  return prefix.length > 0 && !prefix.includes(".");
}

function formatName(name: PeerCertificate["subject"] | undefined): string | null {
  if (!name) return null;
  const parts = [name.CN, name.O].filter(
    (value): value is string => typeof value === "string" && value.length > 0,
  );
  return parts.length > 0 ? parts.join(", ") : null;
}

export async function checkTls(
  hostname: string,
  signal: AbortSignal,
): Promise<CheckResult<TlsData>> {
  const started = Date.now();
  signal.throwIfAborted();

  const { certificate, protocol, cipher, authorizationError } = await handshake(
    hostname,
    signal,
  );

  if (!certificate.valid_to) {
    throw new Error("The server completed a handshake but presented no certificate");
  }

  const sans = parseSans(certificate);
  const now = Date.now();
  const validToMs = Date.parse(certificate.valid_to);
  const validFromMs = Date.parse(certificate.valid_from);

  const daysUntilExpiry = Number.isFinite(validToMs)
    ? Math.floor((validToMs - now) / 86_400_000)
    : null;

  const subjectCn = certificate.subject?.CN;
  const hostnameMatches =
    sans.some((san) => sanMatches(hostname, san)) ||
    (typeof subjectCn === "string" && sanMatches(hostname, subjectCn.toLowerCase()));

  // A self-signed certificate has an identical issuer and subject. Node's
  // error codes for this are checked too, since the DN comparison alone can
  // be fooled by a certificate that merely copies its issuer's DN.
  const selfSigned =
    JSON.stringify(certificate.issuer ?? {}) === JSON.stringify(certificate.subject ?? {}) ||
    authorizationError === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
    authorizationError === "SELF_SIGNED_CERT_IN_CHAIN";

  const data: TlsData = {
    protocol,
    cipher,
    subject: formatName(certificate.subject),
    issuer: formatName(certificate.issuer),
    subjectAltNames: sans,
    validFrom: certificate.valid_from ?? null,
    validTo: certificate.valid_to ?? null,
    daysUntilExpiry,
    keyBits: typeof certificate.bits === "number" ? certificate.bits : null,
    signatureAlgorithm: readSignatureAlgorithm(certificate.raw),
    selfSigned,
    hostnameMatches,
    authorizationError,
  };

  const findings: Finding[] = [];

  // ---- Validity window ----------------------------------------------------
  if (daysUntilExpiry !== null && daysUntilExpiry < 0) {
    findings.push({
      id: "tls.expired",
      check: CHECK,
      severity: "critical",
      title: "Certificate has expired",
      observed: `The certificate expired on ${certificate.valid_to} (${Math.abs(daysUntilExpiry)} days ago).`,
      impact:
        "Browsers show a full-page interstitial warning and most visitors cannot proceed. The site is effectively unreachable, and users trained to click through such warnings are easier to phish.",
      remediation: {
        summary: "Renew the certificate immediately and automate renewal so it cannot lapse again.",
      },
    });
  } else if (daysUntilExpiry !== null && daysUntilExpiry <= EXPIRY_WARNING_DAYS) {
    findings.push({
      id: "tls.expiring",
      check: CHECK,
      severity: daysUntilExpiry <= 7 ? "high" : "medium",
      title: `Certificate expires in ${daysUntilExpiry} day${daysUntilExpiry === 1 ? "" : "s"}`,
      observed: `The certificate is valid until ${certificate.valid_to}.`,
      impact:
        "If renewal does not complete before that date the site becomes unreachable for every visitor.",
      remediation: {
        summary: "Renew now, and set up automated renewal with monitoring.",
      },
    });
  } else if (Number.isFinite(validFromMs) && validFromMs > now) {
    findings.push({
      id: "tls.not-yet-valid",
      check: CHECK,
      severity: "critical",
      title: "Certificate is not yet valid",
      observed: `The certificate's validity begins ${certificate.valid_from}, which is in the future.`,
      impact: "Browsers reject the certificate outright, exactly as they would an expired one.",
      remediation: { summary: "Check the server clock and reissue the certificate if needed." },
    });
  } else if (daysUntilExpiry !== null) {
    findings.push({
      id: "tls.validity.ok",
      check: CHECK,
      severity: "pass",
      title: "Certificate is current",
      observed: `Valid until ${certificate.valid_to} (${daysUntilExpiry} days away).`,
      impact: "The certificate is inside its validity window.",
    });
  }

  // ---- Identity -----------------------------------------------------------
  if (!hostnameMatches) {
    findings.push({
      id: "tls.hostname-mismatch",
      check: CHECK,
      severity: "critical",
      title: "Certificate does not cover this hostname",
      observed: `The certificate is issued for ${
        sans.length > 0 ? sans.join(", ") : (subjectCn ?? "an unknown name")
      }, which does not include ${hostname}.`,
      impact:
        "Browsers cannot confirm they are talking to the right server, so they block the connection with a warning.",
      remediation: {
        summary: `Reissue the certificate with ${hostname} in its Subject Alternative Names.`,
      },
    });
  } else {
    findings.push({
      id: "tls.hostname.ok",
      check: CHECK,
      severity: "pass",
      title: "Certificate covers this hostname",
      observed: `${hostname} is covered by the certificate's names.`,
      impact: "The certificate identifies the host it was served from.",
    });
  }

  if (selfSigned) {
    findings.push({
      id: "tls.self-signed",
      check: CHECK,
      severity: "high",
      title: "Certificate is self-signed",
      observed: `The certificate's issuer and subject are the same (${data.issuer ?? "unknown"}).`,
      impact:
        "No public certificate authority vouches for it, so no browser trusts it by default and every visitor sees a warning.",
      remediation: {
        summary:
          "Replace it with a certificate from a publicly trusted CA. Let's Encrypt issues them free and automatically.",
      },
    });
  } else if (authorizationError && !EXPLAINED_ELSEWHERE.has(authorizationError)) {
    findings.push({
      id: "tls.chain-untrusted",
      check: CHECK,
      severity: "high",
      title: "Certificate chain did not verify",
      observed: `Verification failed with: ${authorizationError}.`,
      impact:
        "Browsers may refuse the connection. This often means an intermediate certificate is missing from what the server sends.",
      remediation: {
        summary:
          "Serve the full chain — your certificate plus every intermediate, in order — not just the leaf.",
      },
    });
  }

  // ---- Protocol and key ---------------------------------------------------
  const legacyProtocol =
    protocol === "TLSv1" || protocol === "TLSv1.1" || protocol === "SSLv3";

  if (legacyProtocol) {
    findings.push({
      id: "tls.legacy-protocol",
      check: CHECK,
      severity: "high",
      title: `Connection negotiated ${protocol}`,
      observed: `The handshake settled on ${protocol}.`,
      impact:
        "TLS 1.0 and 1.1 are deprecated (RFC 8996) and have known weaknesses. Current browsers refuse them outright.",
      remediation: {
        summary: "Disable TLS 1.1 and below; require TLS 1.2 as a minimum, and prefer 1.3.",
        reference: "RFC 8996",
      },
    });
  } else if (protocol) {
    findings.push({
      id: "tls.protocol.ok",
      check: CHECK,
      severity: "pass",
      title: `Connection negotiated ${protocol}`,
      observed: `The handshake settled on ${protocol}${cipher ? ` with ${cipher}` : ""}.`,
      impact: "The negotiated protocol is a current, supported version.",
    });
  }

  // Key size is only meaningful for RSA; EC keys are strong at 256 bits.
  const isEc = typeof certificate.asn1Curve === "string" || typeof certificate.nistCurve === "string";
  if (!isEc && data.keyBits !== null && data.keyBits < MIN_RSA_KEY_BITS) {
    findings.push({
      id: "tls.weak-key",
      check: CHECK,
      severity: "high",
      title: `RSA key is only ${data.keyBits} bits`,
      observed: `The certificate carries a ${data.keyBits}-bit RSA key.`,
      impact: `RSA keys below ${MIN_RSA_KEY_BITS} bits are considered breakable and are no longer issued by public CAs.`,
      remediation: {
        summary: `Reissue with at least a ${MIN_RSA_KEY_BITS}-bit RSA key, or an EC P-256 key.`,
      },
    });
  }

  if (data.signatureAlgorithm && /sha1|md5/i.test(data.signatureAlgorithm)) {
    findings.push({
      id: "tls.weak-signature",
      check: CHECK,
      severity: "high",
      title: "Certificate uses a deprecated signature algorithm",
      observed: `Signature algorithm: ${data.signatureAlgorithm}.`,
      impact:
        "SHA-1 and MD5 are vulnerable to collision attacks, which undermines the certificate's integrity guarantee. Browsers reject them.",
      remediation: { summary: "Reissue the certificate with a SHA-256 signature." },
    });
  }

  return {
    check: CHECK,
    status: "ok",
    findings,
    data,
    durationMs: Date.now() - started,
  };
}
