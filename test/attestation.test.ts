import { describe, it, expect } from "vitest";
import { Wallet } from "ethers";
import {
  signReceipt,
  signProviderAttestation,
  attachAttestation,
  generateEd25519,
  evmSigner,
  HSealProvider,
  type ReceiptInput,
} from "../src/index.js";
import { verifyReceiptBody, verifyProviderBody } from "./server-verify.js";

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

describe("provider attestation", () => {
  it("Hedera Ed25519 provider co-signature verifies", async () => {
    const { signer, publicKeyRaw } = generateEd25519();
    const att = await signProviderAttestation({
      attestation: {
        providerIdentity: "0.0.7777",
        requestHash: "sha256:aa",
        responseHash: "sha256:bb",
        providerIssuedAt: 1_700_000_002,
      },
      signer,
      network: "mainnet",
    });
    expect(att.providerSignatureScheme).toBe("ed25519");
    expect(verifyProviderBody(att, { hederaEd25519Raw: publicKeyRaw })).toBe(true);
  });

  it("EVM provider co-signature verifies", async () => {
    const wallet = Wallet.createRandom();
    const att = await signProviderAttestation({
      attestation: {
        providerIdentity: `eip155:8453:${wallet.address}`,
        requestHash: "sha256:aa",
        responseHash: "sha256:bb",
        providerIssuedAt: 1_700_000_002,
      },
      signer: evmSigner(wallet as unknown as Wallet),
      network: "mainnet",
    });
    expect(att.providerSignatureScheme).toBe("eip712");
    expect(verifyProviderBody(att, {})).toBe(true);
  });

  it("attaches to a caller receipt and the merged body still verifies on both sides", async () => {
    const caller = generateEd25519();
    const provider = generateEd25519();
    const receipt: ReceiptInput = { ...BASE, callerIdentity: "0.0.4242", providerIdentity: "0.0.7777" };
    const signed = await signReceipt({ receipt, signer: caller.signer, network: "mainnet" });

    const att = await signProviderAttestation({
      attestation: {
        providerIdentity: "0.0.7777",
        requestHash: receipt.requestHash,
        responseHash: receipt.responseHash,
        providerIssuedAt: 1_700_000_002,
      },
      signer: provider.signer,
      network: "mainnet",
    });
    const merged = attachAttestation(signed.body, att);

    expect(verifyReceiptBody(merged, { hederaEd25519Raw: caller.publicKeyRaw })).toBe(true);
    expect(
      verifyProviderBody(
        {
          providerIdentity: merged.providerIdentity,
          requestHash: merged.requestHash,
          responseHash: merged.responseHash,
          providerIssuedAt: merged.providerIssuedAt!,
          providerSignature: merged.providerSignature!,
        },
        { hederaEd25519Raw: provider.publicKeyRaw },
      ),
    ).toBe(true);
  });

  it("attachAttestation rejects mismatched hashes", async () => {
    const caller = generateEd25519();
    const provider = generateEd25519();
    const signed = await signReceipt({
      receipt: { ...BASE, callerIdentity: "0.0.4242" },
      signer: caller.signer,
      network: "mainnet",
    });
    const att = await signProviderAttestation({
      attestation: { providerIdentity: "0.0.7777", requestHash: "sha256:DIFFERENT", responseHash: "sha256:bb", providerIssuedAt: 1 },
      signer: provider.signer,
      network: "mainnet",
    });
    expect(() => attachAttestation(signed.body, att)).toThrow(/do not match/);
  });

  it("HSealProvider.attest hashes request/response and verifies", async () => {
    const { signer, publicKeyRaw } = generateEd25519();
    const provider = new HSealProvider({ identity: "0.0.7777", signer, network: "mainnet" });
    const att = await provider.attest({
      request: { method: "tools/call", name: "search" },
      response: { ok: true, rows: 3 },
      providerIssuedAt: 1_700_000_002,
    });
    expect(att.requestHash.startsWith("sha256:")).toBe(true);
    expect(verifyProviderBody(att, { hederaEd25519Raw: publicKeyRaw })).toBe(true);
  });
});
