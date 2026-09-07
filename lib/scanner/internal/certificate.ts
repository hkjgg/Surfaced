/**
 * Minimal DER reader for the one field Node does not expose.
 *
 * `tls.TLSSocket.getPeerCertificate()` returns subject, issuer, validity,
 * key size and SANs, but not the signature algorithm — there is no `sigalg`
 * property in any current Node version. Without it the "certificate is signed
 * with SHA-1" check can never fire, which is worse than not having the check
 * at all: it looks like coverage and provides none.
 *
 * So the algorithm is read from the certificate's own DER bytes, which the
 * socket does provide as `raw`. Only the outer structure is walked, never the
 * signature or key material:
 *
 *   Certificate ::= SEQUENCE {
 *     tbsCertificate       TBSCertificate,      -- skipped
 *     signatureAlgorithm   AlgorithmIdentifier, -- read
 *     signatureValue       BIT STRING           -- ignored
 *   }
 */

const TAG_SEQUENCE = 0x30;
const TAG_OID = 0x06;

/** Signature algorithm OIDs, by dotted notation. */
const SIGNATURE_OIDS: Readonly<Record<string, string>> = Object.freeze({
  "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
  "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
  "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
  "1.2.840.113549.1.1.10": "rsassaPss",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.10040.4.3": "dsaWithSha1",
  "1.2.840.10045.4.1": "ecdsaWithSHA1",
  "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
  "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
  "1.2.840.10045.4.3.4": "ecdsaWithSHA512",
  "1.3.101.112": "ed25519",
  "1.3.101.113": "ed448",
});

interface Tlv {
  readonly tag: number;
  readonly valueStart: number;
  readonly valueEnd: number;
}

/** Read one tag-length-value triple starting at `offset`. */
function readTlv(buffer: Uint8Array, offset: number): Tlv | null {
  if (offset + 2 > buffer.length) return null;

  const tag = buffer[offset];
  const firstLengthByte = buffer[offset + 1];
  if (tag === undefined || firstLengthByte === undefined) return null;

  let length = 0;
  let cursor = offset + 2;

  if (firstLengthByte < 0x80) {
    length = firstLengthByte;
  } else {
    // Long form: the low 7 bits give the number of length bytes that follow.
    const lengthBytes = firstLengthByte & 0x7f;
    if (lengthBytes === 0 || lengthBytes > 4) return null;
    if (offset + 2 + lengthBytes > buffer.length) return null;

    for (let i = 0; i < lengthBytes; i += 1) {
      const byte = buffer[offset + 2 + i];
      if (byte === undefined) return null;
      length = length * 256 + byte;
    }
    cursor = offset + 2 + lengthBytes;
  }

  const valueEnd = cursor + length;
  if (valueEnd > buffer.length) return null;

  return { tag, valueStart: cursor, valueEnd };
}

/** Decode OID contents into dotted notation. */
function decodeOid(buffer: Uint8Array, start: number, end: number): string | null {
  const first = buffer[start];
  if (first === undefined) return null;

  // The first byte packs the first two arcs as 40 * a + b.
  const parts: number[] = [Math.floor(first / 40), first % 40];

  let value = 0;
  for (let i = start + 1; i < end; i += 1) {
    const byte = buffer[i];
    if (byte === undefined) return null;

    value = value * 128 + (byte & 0x7f);
    if ((byte & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }

  return parts.join(".");
}

/**
 * Returns a human-readable signature algorithm name, the raw OID when it is
 * unrecognised, or null when the certificate could not be parsed.
 */
export function readSignatureAlgorithm(raw: Uint8Array | undefined): string | null {
  if (!raw || raw.length === 0) return null;

  const certificate = readTlv(raw, 0);
  if (!certificate || certificate.tag !== TAG_SEQUENCE) return null;

  // First element of the certificate is tbsCertificate; skip over it.
  const tbs = readTlv(raw, certificate.valueStart);
  if (!tbs) return null;

  const algorithmId = readTlv(raw, tbs.valueEnd);
  if (!algorithmId || algorithmId.tag !== TAG_SEQUENCE) return null;

  const oid = readTlv(raw, algorithmId.valueStart);
  if (!oid || oid.tag !== TAG_OID) return null;

  const dotted = decodeOid(raw, oid.valueStart, oid.valueEnd);
  if (!dotted) return null;

  return SIGNATURE_OIDS[dotted] ?? dotted;
}
