// Payment-commitment placement.
//
// When an H-Series 402 challenge advertises `extra.paymentCommitment`, an
// OIDC-identity or cross-chain payer must embed that value in the on-chain
// payment they make. The backend then reads it back off the settled transaction
// and binds the payment to this challenge (see the facilitators' commitmentCarrier
// on the server). This module is the INVERSE of that read: it tells the caller
// exactly where the commitment goes for the rail they are paying on, and returns
// the ready-to-use value.
//
// The SDK does not build or sign the payment itself - it holds no payment keys.
// The caller constructs the payment with their own wallet and attaches the value
// this module returns. A full payment-building flow is on the roadmap (see README).
//
// Carrier per rail (must match the server's commitmentCarrier):
//   Hedera / Solana   transaction memo / SPL memo  -> the 64-char hex string
//   XRPL              a Memo's MemoData (hex)       -> the 64-char hex string
//   Stellar          classic MEMO_HASH (32 bytes)  -> the raw 32 bytes
//   EVM (USDC)       EIP-3009 transferWithAuthorization nonce (bytes32) -> 0x + hex
// Plain EVM/Stellar-USDC value transfers carry no commitment and stay fail-closed.

const HEX64 = /^[0-9a-f]{64}$/;

/** Pull the advertised commitment out of a parsed 402 challenge body, or undefined. */
export function commitmentFromChallenge(body: unknown): string | undefined {
  const accepts = (body as { accepts?: Array<{ extra?: Record<string, unknown> }> } | null)?.accepts;
  if (!Array.isArray(accepts)) return undefined;
  for (const a of accepts) {
    const c = a?.extra?.paymentCommitment;
    if (typeof c === "string" && c) return c;
  }
  return undefined;
}

/** Validate and normalize an advertised commitment to 64-char lowercase hex. Throws if malformed. */
export function normalizeCommitment(commitment: string): string {
  let s = typeof commitment === "string" ? commitment.trim() : "";
  if (s.startsWith("0x") || s.startsWith("0X")) s = s.slice(2);
  s = s.toLowerCase();
  if (!HEX64.test(s)) throw new Error("commitment must be a 32-byte hex string (64 hex chars)");
  return s;
}

export type CommitmentCarrier =
  | "memo-hex"
  | "xrpl-memo"
  | "stellar-memo-hash"
  | "evm-eip3009-nonce"
  | "none";

export interface CommitmentPlacement {
  carrier: CommitmentCarrier;
  /** memo-hex (Hedera/Solana tx memo) and xrpl-memo (Memos[].Memo.MemoData): set this hex string. */
  hex?: string;
  /** stellar-memo-hash: the raw 32 bytes for Memo.hash(). */
  bytes?: Uint8Array;
  /** evm-eip3009-nonce: the 0x-prefixed bytes32 nonce for transferWithAuthorization. */
  nonce?: string;
}

// --- per-carrier primitives (use directly when you know your rail) ---

/** Hedera / Solana transaction memo: the commitment as a 64-char hex string. */
export function commitmentMemoText(commitment: string): string {
  return normalizeCommitment(commitment);
}

/** XRPL Memos[].Memo.MemoData: the commitment hex (the server accepts the raw 32 bytes). */
export function commitmentXrplMemoData(commitment: string): string {
  return normalizeCommitment(commitment).toUpperCase(); // XRPL MemoData is conventionally upper hex
}

/** Stellar classic MEMO_HASH: the raw 32 bytes (pass to Memo.hash()). */
export function commitmentStellarMemoHash(commitment: string): Uint8Array {
  return Uint8Array.from(Buffer.from(normalizeCommitment(commitment), "hex"));
}

/** EVM EIP-3009 transferWithAuthorization nonce: the 0x-prefixed bytes32. */
export function commitmentEvmNonce(commitment: string): string {
  return "0x" + normalizeCommitment(commitment);
}

// --- dispatcher: pick the carrier from the x402 rail / network label ---

/**
 * Given the rail you are paying on (the `accepts[].network` label from the 402,
 * e.g. "hedera-mainnet", "solana-mainnet-sol", "xrpl:0", "stellar:pubnet",
 * "eip155:8453"), return where the commitment goes and the value to use.
 * Returns carrier "none" for rails with no commitment carrier (a plain EVM or
 * Stellar-USDC value transfer); those stay fail-closed for the OIDC/cross-chain
 * cases by design.
 */
export function placeCommitment(commitment: string, network: string): CommitmentPlacement {
  const hex = normalizeCommitment(commitment);
  const n = network.toLowerCase();
  if (n.startsWith("hedera") || n.startsWith("solana")) return { carrier: "memo-hex", hex };
  if (n.startsWith("xrpl")) return { carrier: "xrpl-memo", hex: hex.toUpperCase() };
  if (n.startsWith("stellar")) return { carrier: "stellar-memo-hash", bytes: commitmentStellarMemoHash(hex) };
  if (n.startsWith("eip155") || n.startsWith("base")) return { carrier: "evm-eip3009-nonce", nonce: "0x" + hex };
  return { carrier: "none" };
}
