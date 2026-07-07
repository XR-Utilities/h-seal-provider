import { describe, it, expect } from "vitest";
import { signReceipt, generateEd25519, type ReceiptInput } from "../src/index.js";
import { verifyReceiptBody } from "./server-verify.js";

const RECEIPT: Omit<ReceiptInput, "callerIdentity"> = {
  taskId: "task-1",
  serviceEndpoint: "https://api.example.com/run",
  requestHash: "sha256:aa",
  responseHash: "sha256:bb",
  resultStatus: "success",
  startedAt: 1_700_000_000,
  completedAt: 1_700_000_001,
  latencyMs: 1000,
  receiptTopicId: "0.0.5555",
  issuedAt: 1_700_000_002,
  method: "POST",
  httpStatus: 200,
};

describe("Hedera Ed25519 receipt signing", () => {
  it("produces a v2 signature the server verifier accepts (bare 0.0.x id)", async () => {
    const { signer, publicKeyRaw } = generateEd25519();
    const signed = await signReceipt({
      receipt: { ...RECEIPT, callerIdentity: "0.0.4242" },
      signer,
      network: "mainnet",
    });
    expect(signed.schemaVersion).toBe(2);
    expect(verifyReceiptBody(signed.body, { hederaEd25519Raw: publicKeyRaw })).toBe(true);
  });

  it("produces a v4 signature when requestId is present", async () => {
    const { signer, publicKeyRaw } = generateEd25519();
    const signed = await signReceipt({
      receipt: { ...RECEIPT, callerIdentity: "hedera:mainnet:0.0.4242", requestId: "req-9" },
      signer,
      network: "mainnet",
    });
    expect(signed.schemaVersion).toBe(4);
    expect(signed.body.requestId).toBe("req-9");
    expect(verifyReceiptBody(signed.body, { hederaEd25519Raw: publicKeyRaw })).toBe(true);
  });

  it("rejects a signature from a different key", async () => {
    const { signer } = generateEd25519();
    const other = generateEd25519();
    const signed = await signReceipt({
      receipt: { ...RECEIPT, callerIdentity: "0.0.4242" },
      signer,
      network: "mainnet",
    });
    expect(verifyReceiptBody(signed.body, { hederaEd25519Raw: other.publicKeyRaw })).toBe(false);
  });

  it("rejects a tampered payload", async () => {
    const { signer, publicKeyRaw } = generateEd25519();
    const signed = await signReceipt({
      receipt: { ...RECEIPT, callerIdentity: "0.0.4242" },
      signer,
      network: "mainnet",
    });
    const tampered = { ...signed.body, latencyMs: 9999 };
    expect(verifyReceiptBody(tampered, { hederaEd25519Raw: publicKeyRaw })).toBe(false);
  });
});
