import { describe, it, expect } from "vitest";
import { signReceipt, generateEd25519, type ReceiptInput } from "../src/index.js";
import { verifyReceiptBody, stellarGFromEd25519 } from "./server-verify.js";

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

describe("Stellar receipt signing", () => {
  it("emits an ed25519 signature over the digest that verifies for the G... account", async () => {
    const { signer, publicKeyRaw } = generateEd25519();
    const address = stellarGFromEd25519(publicKeyRaw);
    const receipt: ReceiptInput = { ...BASE, callerIdentity: `stellar:pubnet:${address}` };
    const signed = await signReceipt({ receipt, signer, network: "mainnet" });
    expect(signed.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(verifyReceiptBody(signed.body, {})).toBe(true);
  });
});
