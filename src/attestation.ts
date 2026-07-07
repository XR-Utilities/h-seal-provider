import { PROVIDER_ATTEST_TYPES, type HederaNetwork } from "./domain.js";
import { parseIdentity, nowSeconds } from "./identity.js";
import { signFor } from "./sign-core.js";
import type { Signer } from "./signers.js";
import type { AnchorRequestBody } from "./receipt.js";

// What a provider signs: the subset it can compute from the bytes it exchanged.
// No taskId, latency, or caller timing here; only the request/response hashes and
// the provider's own identity and time.
export interface ProviderAttestationInput {
  providerIdentity: string;
  requestHash: string;
  responseHash: string;
  providerIssuedAt?: number;
}

// The fields the anchor route reads for a provider co-signature. Merge these onto
// a caller receipt body before anchoring.
export interface ProviderAttestation {
  providerIdentity: string;
  providerSignature: string;
  // A hint only. The server verifies by the providerIdentity's CAIP-10 namespace
  // and stores the scheme it actually verified.
  providerSignatureScheme: string;
  providerIssuedAt: number;
  requestHash: string;
  responseHash: string;
}

export interface SignProviderAttestationOptions {
  attestation: ProviderAttestationInput;
  signer: Signer;
  network: HederaNetwork;
}

// Co-sign a request/response pair as the provider. This is the headline
// integration: an MCP server computes the two hashes from what it received and
// returned, calls this once, and hands the result back to the caller (or anchors
// it itself).
export async function signProviderAttestation(
  opts: SignProviderAttestationOptions,
): Promise<ProviderAttestation> {
  const { attestation, signer, network } = opts;
  const providerIssuedAt = attestation.providerIssuedAt ?? nowSeconds();
  const identity = parseIdentity(attestation.providerIdentity, network);

  const payload = {
    providerIdentity: attestation.providerIdentity,
    requestHash: attestation.requestHash,
    responseHash: attestation.responseHash,
    providerIssuedAt,
  };

  const providerSignature = await signFor(identity, signer, {
    kind: "provider_attest",
    payload,
    eip712Types: PROVIDER_ATTEST_TYPES,
    eip712Message: payload,
  });

  return {
    providerIdentity: attestation.providerIdentity,
    providerSignature,
    providerSignatureScheme: signer.kind === "evm" ? "eip712" : "ed25519",
    providerIssuedAt,
    requestHash: attestation.requestHash,
    responseHash: attestation.responseHash,
  };
}

// Merge a provider co-signature onto a caller receipt body. The provider's
// requestHash/responseHash must match the receipt's, or the server verifies the
// caller signature against different bytes than the provider attested to; this
// guard fails fast instead of letting the anchor be rejected on chain.
//
// providerIdentity is inside the caller's signed payload, so it must not be
// mutated here: replacing it would make the server reconstruct a different
// preimage and the caller signature would no longer verify. We require it to
// match what the caller already signed and fail fast on mismatch, the same way
// the request/response hashes are guarded.
export function attachAttestation(
  body: AnchorRequestBody,
  attestation: ProviderAttestation,
): AnchorRequestBody {
  if (attestation.requestHash !== body.requestHash || attestation.responseHash !== body.responseHash) {
    throw new Error("provider attestation hashes do not match the receipt requestHash/responseHash");
  }
  if (attestation.providerIdentity !== body.providerIdentity) {
    throw new Error("provider attestation providerIdentity does not match the caller-signed receipt providerIdentity");
  }
  return {
    ...body,
    providerSignature: attestation.providerSignature,
    providerSignatureScheme: attestation.providerSignatureScheme,
    providerIssuedAt: attestation.providerIssuedAt,
  };
}
