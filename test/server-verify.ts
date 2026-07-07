// Independent reimplementation of H-Seal's verification, transcribed from
// src/modules/tip712.ts and src/routes/anchor.ts at commit c1e31c4. The SDK
// builds and signs; this verifies straight off the wire body the SDK produces.
// If a signature verifies here, the live server accepts it (given the mirror
// returns the matching key). Deliberately does NOT import the SDK's own helpers,
// so the test is a genuine cross-check rather than the SDK validating itself.

import { createHash, verify as nodeVerify } from "node:crypto";
import { verifyTypedData, getAddress, type TypedDataField } from "ethers";
import { StrKey } from "@stellar/stellar-sdk";

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

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
function hashCanonicalJson(value: unknown): Buffer {
  return createHash("sha256").update(canonicalJson(value)).digest();
}

export function nodeVerifyEd25519(rawPub: Uint8Array, msg: Buffer, sig: Uint8Array): boolean {
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const spki = Buffer.concat([spkiPrefix, Buffer.from(rawPub)]);
  return nodeVerify(null, msg, { key: spki, format: "der", type: "spki" }, Buffer.from(sig));
}

function decodeHex(s: string): Buffer {
  const trimmed = s.startsWith("0x") ? s.slice(2) : s;
  return Buffer.from(trimmed, "hex");
}

const V1: TypedDataField[] = [
  { name: "taskId", type: "string" },
  { name: "serviceEndpoint", type: "string" },
  { name: "requestHash", type: "string" },
  { name: "responseHash", type: "string" },
  { name: "resultStatus", type: "string" },
  { name: "startedAt", type: "uint256" },
  { name: "completedAt", type: "uint256" },
  { name: "latencyMs", type: "uint256" },
  { name: "callerIdentity", type: "string" },
  { name: "providerIdentity", type: "string" },
  { name: "receiptTopicId", type: "string" },
  { name: "issuedAt", type: "uint256" },
];
const V2_EXTRA: TypedDataField[] = [
  { name: "schemaVersion", type: "uint256" },
  { name: "method", type: "string" },
  { name: "httpStatus", type: "uint256" },
  { name: "correlationId", type: "string" },
  { name: "amountPaid", type: "string" },
  { name: "amountCurrency", type: "string" },
];

function buildDomain(chainId: number) {
  return { name: "H-Seal", version: "1", chainId, verifyingContract: ZERO_ADDRESS };
}

// Mirrors the anchor route's payload assembly.
export function reconstructPayload(body: Record<string, any>): Record<string, unknown> {
  const sv = body.schemaVersion ?? 1;
  const p: Record<string, unknown> = {
    taskId: body.taskId,
    serviceEndpoint: body.serviceEndpoint,
    requestHash: body.requestHash,
    responseHash: body.responseHash,
    resultStatus: body.resultStatus,
    startedAt: body.startedAt,
    completedAt: body.completedAt,
    latencyMs: body.latencyMs,
    callerIdentity: body.callerIdentity,
    providerIdentity: body.providerIdentity ?? "",
    receiptTopicId: body.receiptTopicId,
    issuedAt: body.issuedAt,
  };
  if (sv >= 2) {
    Object.assign(p, {
      schemaVersion: sv,
      method: body.method ?? "",
      httpStatus: body.httpStatus ?? 0,
      correlationId: body.correlationId ?? "",
      amountPaid: body.amountPaid ?? "",
      amountCurrency: body.amountCurrency ?? "",
    });
  }
  if (sv === 4) p.requestId = body.requestId ?? "";
  return p;
}

// Mirrors tip712 eip712TypeAndMessage.
function eip712View(payload: Record<string, any>): { types: Record<string, TypedDataField[]>; message: Record<string, unknown> } {
  const sv = payload.schemaVersion;
  if (sv === 2 || sv === 4) {
    const v2Message: Record<string, unknown> = {
      taskId: payload.taskId,
      serviceEndpoint: payload.serviceEndpoint,
      requestHash: payload.requestHash,
      responseHash: payload.responseHash,
      resultStatus: payload.resultStatus,
      startedAt: payload.startedAt,
      completedAt: payload.completedAt,
      latencyMs: payload.latencyMs,
      callerIdentity: payload.callerIdentity,
      providerIdentity: payload.providerIdentity,
      receiptTopicId: payload.receiptTopicId,
      issuedAt: payload.issuedAt,
      schemaVersion: payload.schemaVersion,
      method: payload.method ?? "",
      httpStatus: payload.httpStatus ?? 0,
      correlationId: payload.correlationId ?? "",
      amountPaid: payload.amountPaid ?? "",
      amountCurrency: payload.amountCurrency ?? "",
    };
    if (sv === 4) {
      return { types: { AnchorReceipt: [...V1, ...V2_EXTRA, { name: "requestId", type: "string" }] }, message: { ...v2Message, requestId: payload.requestId ?? "" } };
    }
    return { types: { AnchorReceipt: [...V1, ...V2_EXTRA] }, message: v2Message };
  }
  return { types: { AnchorReceipt: V1 }, message: payload };
}

function parseCaip10(id: string): { chain: string; address: string } | null {
  const parts = id.split(":");
  if (parts.length < 3) return null;
  return { chain: `${parts[0]}:${parts[1]}`, address: parts.slice(2).join(":") };
}

// Verify a caller receipt body against the appropriate chain, exactly as the
// server would. For Hedera the on-chain key is supplied (the mirror's job live).
export function verifyReceiptBody(
  body: Record<string, any>,
  keys: { hederaEd25519Raw?: Uint8Array; network?: "mainnet" | "testnet" },
): boolean {
  const payload = reconstructPayload(body);
  const id: string = body.callerIdentity;
  const parsed = parseCaip10(id);
  const namespace = parsed ? parsed.chain.split(":")[0] : "hedera";

  if (namespace === "eip155") {
    const ref = Number(parsed!.chain.split(":")[1]);
    const { types, message } = eip712View(payload);
    const recovered = verifyTypedData(buildDomain(ref), types, message, body.signature);
    return getAddress(recovered) === getAddress(parsed!.address);
  }
  if (namespace === "hedera") {
    if (!keys.hederaEd25519Raw) throw new Error("hedera verify needs the ed25519 raw key");
    const digestHex = hashCanonicalJson({ kind: "anchor", payload }).toString("hex");
    const prefixed = Buffer.from(`\x19Hedera Signed Message:\n${digestHex.length}${digestHex}`, "utf-8");
    return nodeVerifyEd25519(keys.hederaEd25519Raw, prefixed, decodeHex(body.signature));
  }
  if (namespace === "xrpl") {
    const [pubKeyHex, sigHex] = body.signature.split(":");
    const pubBytes = decodeHex(pubKeyHex);
    const rawPub = pubBytes.length === 33 ? pubBytes.subarray(1) : pubBytes;
    if (xrplAddressFromEd25519(Buffer.concat([Buffer.from([0xed]), rawPub])) !== parsed!.address) return false;
    const digest = hashCanonicalJson({ kind: "anchor", payload });
    return nodeVerifyEd25519(rawPub, digest, decodeHex(sigHex));
  }
  if (namespace === "solana") {
    const rawPub = decodeBase58Solana(parsed!.address);
    const digest = hashCanonicalJson({ kind: "anchor", payload });
    const text = Buffer.from(canonicalJson({ kind: "anchor", payload }), "utf-8");
    const sig = decodeHex(body.signature);
    return nodeVerifyEd25519(rawPub, digest, sig) || nodeVerifyEd25519(rawPub, text, sig);
  }
  if (namespace === "stellar") {
    const rawPub = Buffer.from(StrKey.decodeEd25519PublicKey(parsed!.address));
    const digest = hashCanonicalJson({ kind: "anchor", payload });
    const text = Buffer.from(canonicalJson({ kind: "anchor", payload }), "utf-8");
    const sig = decodeHex(body.signature);
    return nodeVerifyEd25519(rawPub, digest, sig) || nodeVerifyEd25519(rawPub, text, sig);
  }
  throw new Error(`unsupported namespace ${namespace}`);
}

// Verify a provider attestation, as the server's verifyProviderAttestation does.
export function verifyProviderBody(
  att: { providerIdentity: string; requestHash: string; responseHash: string; providerIssuedAt: number; providerSignature: string },
  keys: { hederaEd25519Raw?: Uint8Array },
): boolean {
  const payload = {
    providerIdentity: att.providerIdentity,
    requestHash: att.requestHash,
    responseHash: att.responseHash,
    providerIssuedAt: att.providerIssuedAt,
  };
  const parsed = parseCaip10(att.providerIdentity);
  const namespace = parsed ? parsed.chain.split(":")[0] : "hedera";

  if (namespace === "eip155") {
    const ref = Number(parsed!.chain.split(":")[1]);
    const types = {
      ProviderAttestation: [
        { name: "providerIdentity", type: "string" },
        { name: "requestHash", type: "string" },
        { name: "responseHash", type: "string" },
        { name: "providerIssuedAt", type: "uint256" },
      ],
    };
    const recovered = verifyTypedData(buildDomain(ref), types, payload, att.providerSignature);
    return getAddress(recovered) === getAddress(parsed!.address);
  }
  if (namespace === "hedera") {
    if (!keys.hederaEd25519Raw) throw new Error("hedera verify needs the ed25519 raw key");
    const digestHex = hashCanonicalJson({ kind: "provider_attest", payload }).toString("hex");
    const prefixed = Buffer.from(`\x19Hedera Signed Message:\n${digestHex.length}${digestHex}`, "utf-8");
    return nodeVerifyEd25519(keys.hederaEd25519Raw, prefixed, decodeHex(att.providerSignature));
  }
  throw new Error(`unsupported provider namespace ${namespace}`);
}

// Address derivation helpers (server side), so tests can build identities whose
// address genuinely derives from the generated key.
export function xrplAddressFromEd25519(pubKey33: Uint8Array): string {
  const sha = createHash("sha256").update(pubKey33).digest();
  const accountId = createHash("ripemd160").update(sha).digest();
  const versioned = Buffer.concat([Buffer.from([0x00]), accountId]);
  const checksum = createHash("sha256").update(createHash("sha256").update(versioned).digest()).digest().subarray(0, 4);
  return encodeBase58Ripple(Buffer.concat([versioned, checksum]));
}
function encodeBase58Ripple(buf: Buffer): string {
  const ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
  let num = 0n;
  for (const byte of buf) num = num * 256n + BigInt(byte);
  let encoded = "";
  while (num > 0n) {
    encoded = ALPHABET[Number(num % 58n)] + encoded;
    num /= 58n;
  }
  for (const byte of buf) {
    if (byte !== 0) break;
    encoded = ALPHABET[0] + encoded;
  }
  return encoded;
}
export function stellarGFromEd25519(rawPub: Buffer): string {
  return StrKey.encodeEd25519PublicKey(rawPub);
}
export function solanaBase58FromPub(rawPub: Buffer): string {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = 0n;
  for (const byte of rawPub) num = num * 256n + BigInt(byte);
  let encoded = "";
  while (num > 0n) {
    encoded = ALPHABET[Number(num % 58n)] + encoded;
    num /= 58n;
  }
  for (const byte of rawPub) {
    if (byte !== 0) break;
    encoded = ALPHABET[0] + encoded;
  }
  return encoded;
}
function decodeBase58Solana(s: string): Buffer {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = 0n;
  for (const c of s) {
    const idx = ALPHABET.indexOf(c);
    if (idx < 0) throw new Error(`invalid base58 char: ${c}`);
    num = num * 58n + BigInt(idx);
  }
  return Buffer.from(num.toString(16).padStart(64, "0"), "hex");
}
