import { createHash } from "node:crypto";

// Deterministic JSON used as the signing preimage for the ed25519 chains
// (Hedera-Ed25519, XRPL, Solana). This MUST stay byte-for-byte identical to
// H-Seal's canonicalJson in src/modules/tip712.ts: the server re-canonicalizes
// the reconstructed payload and verifies the signature against that exact text.
// Any divergence (key order, separators) changes the digest and every signature
// this SDK produces would be rejected.
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      out[k] = sortKeys((v as Record<string, unknown>)[k]);
    }
    return out;
  }
  return v;
}

export function sha256(buf: Buffer | string): Buffer {
  return createHash("sha256").update(buf).digest();
}

// sha256 over the canonical JSON of value. Matches H-Seal's hashCanonicalJson,
// the 32-byte digest the ed25519 chains sign.
export function hashCanonicalJson(value: unknown): Buffer {
  return sha256(canonicalJson(value));
}

// Convenience hash for a receipt's requestHash / responseHash fields. Those are
// free-form strings on the wire (the server does not interpret them), but both
// the caller and the provider co-signer must agree on the same value, so the
// SDK standardizes on the sha256 hex of the canonical JSON of the payload (or of
// the raw bytes when a string/Buffer is passed). Prefix "sha256:" makes the
// scheme self-describing for downstream verifiers.
export function sha256Hex(value: unknown): string {
  const digest =
    typeof value === "string" || Buffer.isBuffer(value)
      ? sha256(value as Buffer | string)
      : hashCanonicalJson(value);
  return `sha256:${digest.toString("hex")}`;
}
