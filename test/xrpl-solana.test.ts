import { describe, it, expect } from "vitest";
import { signReceipt, generateEd25519, type ReceiptInput } from "../src/index.js";
import { verifyReceiptBody, xrplAddressFromEd25519, solanaBase58FromPub } from "./server-verify.js";

const BASE = {
  taskId: "task-1",
  serviceEndpoint: "https://api.example.com/run",
  requestHash: "sha256:aa",
  responseHash: "sha256:bb",
  resultStatus: "success" as const,
  startedAt: 1_700_000_000,
  completedAt: 1_700_000_001,
  latencyMs: 1000,
  receiptTopicId: "0.0.5555",
  issuedAt: 1_700_000_002,
};

describe("XRPL receipt signing", () => {
  it("emits pubkey:sig over the canonical digest and the address derives from the key", async () => {
    const { signer, publicKeyRaw } = generateEd25519();
    const pub33 = Buffer.concat([Buffer.from([0xed]), publicKeyRaw]);
    const address = xrplAddressFromEd25519(pub33);
    const receipt: ReceiptInput = { ...BASE, callerIdentity: `xrpl:0:${address}` };
    const signed = await signReceipt({ receipt, signer, network: "mainnet" });
    expect(signed.signature).toMatch(/^ed[0-9a-f]{64}:[0-9a-f]{128}$/);
    expect(verifyReceiptBody(signed.body, {})).toBe(true);
  });
});

describe("Solana receipt signing", () => {
  it("emits an ed25519 signature over the digest that verifies for the base58 pubkey", async () => {
    const { signer, publicKeyRaw } = generateEd25519();
    const address = solanaBase58FromPub(publicKeyRaw);
    const receipt: ReceiptInput = { ...BASE, callerIdentity: `solana:mainnet:${address}` };
    const signed = await signReceipt({ receipt, signer, network: "mainnet" });
    expect(signed.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(verifyReceiptBody(signed.body, {})).toBe(true);
  });
});
