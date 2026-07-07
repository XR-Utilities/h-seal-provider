import { describe, it, expect } from "vitest";
import {
  commitmentFromChallenge,
  normalizeCommitment,
  placeCommitment,
  commitmentMemoText,
  commitmentXrplMemoData,
  commitmentStellarMemoHash,
  commitmentEvmNonce,
} from "../src/commitment.js";

const C = "a".repeat(64); // a valid-shaped 32-byte commitment

describe("commitmentFromChallenge", () => {
  it("pulls extra.paymentCommitment from a 402 body", () => {
    const body = { accepts: [{ network: "hedera-mainnet", extra: { tokenDecimals: 6 } }, { network: "eip155:8453", extra: { paymentCommitment: C } }] };
    expect(commitmentFromChallenge(body)).toBe(C);
  });
  it("returns undefined when absent / malformed input", () => {
    expect(commitmentFromChallenge({ accepts: [{ extra: {} }] })).toBeUndefined();
    expect(commitmentFromChallenge(null)).toBeUndefined();
    expect(commitmentFromChallenge({})).toBeUndefined();
  });
});

describe("normalizeCommitment", () => {
  it("accepts 64-hex, strips 0x, lowercases", () => {
    expect(normalizeCommitment(C)).toBe(C);
    expect(normalizeCommitment("0x" + "A".repeat(64))).toBe(C);
  });
  it("throws on malformed input", () => {
    expect(() => normalizeCommitment("a".repeat(63))).toThrow();
    expect(() => normalizeCommitment("g".repeat(64))).toThrow();
    expect(() => normalizeCommitment("")).toThrow();
  });
});

describe("per-carrier primitives", () => {
  it("memo text is the hex string (Hedera/Solana)", () => {
    expect(commitmentMemoText(C)).toBe(C);
  });
  it("XRPL MemoData is upper hex", () => {
    expect(commitmentXrplMemoData(C)).toBe(C.toUpperCase());
  });
  it("Stellar MEMO_HASH is the raw 32 bytes", () => {
    const b = commitmentStellarMemoHash(C);
    expect(b).toBeInstanceOf(Uint8Array);
    expect(b.length).toBe(32);
    expect(Buffer.from(b).toString("hex")).toBe(C);
  });
  it("EVM nonce is 0x-prefixed bytes32", () => {
    expect(commitmentEvmNonce(C)).toBe("0x" + C);
  });
});

describe("placeCommitment dispatcher", () => {
  it("Hedera + Solana -> memo-hex", () => {
    for (const n of ["hedera-mainnet", "hedera-mainnet-hbar", "solana-mainnet-sol", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"]) {
      expect(placeCommitment(C, n)).toEqual({ carrier: "memo-hex", hex: C });
    }
  });
  it("XRPL -> xrpl-memo (upper hex)", () => {
    expect(placeCommitment(C, "xrpl:0")).toEqual({ carrier: "xrpl-memo", hex: C.toUpperCase() });
    expect(placeCommitment(C, "xrpl-mainnet-xrp").carrier).toBe("xrpl-memo");
  });
  it("Stellar -> stellar-memo-hash (32 bytes)", () => {
    const p = placeCommitment(C, "stellar:pubnet");
    expect(p.carrier).toBe("stellar-memo-hash");
    expect(p.bytes?.length).toBe(32);
  });
  it("EVM -> evm-eip3009-nonce", () => {
    expect(placeCommitment(C, "eip155:8453")).toEqual({ carrier: "evm-eip3009-nonce", nonce: "0x" + C });
    expect(placeCommitment(C, "base-mainnet").carrier).toBe("evm-eip3009-nonce");
  });
  it("unknown rail -> none", () => {
    expect(placeCommitment(C, "future-chain")).toEqual({ carrier: "none" });
  });
});
