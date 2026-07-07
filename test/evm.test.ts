import { describe, it, expect } from "vitest";
import { Wallet } from "ethers";
import { signReceipt, evmSigner, type ReceiptInput } from "../src/index.js";
import { verifyReceiptBody } from "./server-verify.js";

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

describe("EVM (eip155) receipt signing", () => {
  it("verifies a v2 EIP-712 receipt against the recovered address (Base, chain 8453)", async () => {
    const wallet = Wallet.createRandom();
    const receipt: ReceiptInput = {
      ...BASE,
      callerIdentity: `eip155:8453:${wallet.address}`,
      method: "POST",
      httpStatus: 200,
    };
    const signed = await signReceipt({ receipt, signer: evmSigner(wallet as unknown as Wallet), network: "mainnet" });
    expect(signed.schemaVersion).toBe(2);
    expect(verifyReceiptBody(signed.body, {})).toBe(true);
  });

  it("verifies a v1 legacy receipt", async () => {
    const wallet = Wallet.createRandom();
    const receipt: ReceiptInput = {
      ...BASE,
      callerIdentity: `eip155:8453:${wallet.address}`,
      schemaVersion: 1,
    };
    const signed = await signReceipt({ receipt, signer: evmSigner(wallet as unknown as Wallet), network: "mainnet" });
    expect(signed.schemaVersion).toBe(1);
    expect(signed.body.schemaVersion).toBeUndefined();
    expect(verifyReceiptBody(signed.body, {})).toBe(true);
  });

  it("verifies a v4 receipt with requestId", async () => {
    const wallet = Wallet.createRandom();
    const receipt: ReceiptInput = {
      ...BASE,
      callerIdentity: `eip155:8453:${wallet.address}`,
      requestId: "req-42",
    };
    const signed = await signReceipt({ receipt, signer: evmSigner(wallet as unknown as Wallet), network: "mainnet" });
    expect(signed.schemaVersion).toBe(4);
    expect(verifyReceiptBody(signed.body, {})).toBe(true);
  });

  it("fails verification when the address in the identity is not the signer", async () => {
    const wallet = Wallet.createRandom();
    const impostor = Wallet.createRandom();
    const receipt: ReceiptInput = {
      ...BASE,
      callerIdentity: `eip155:8453:${impostor.address}`,
    };
    const signed = await signReceipt({ receipt, signer: evmSigner(wallet as unknown as Wallet), network: "mainnet" });
    expect(verifyReceiptBody(signed.body, {})).toBe(false);
  });
});
