import { sha256Hex } from "./canonical.js";
import type { HederaNetwork } from "./domain.js";
import { signProviderAttestation, type ProviderAttestation } from "./attestation.js";
import type { Signer } from "./signers.js";

export interface HSealProviderOptions {
  // The provider's CAIP-10 identity (or a bare Hedera 0.0.x account).
  identity: string;
  // Signer matching the identity's on-chain key (ed25519Signer or evmSigner).
  signer: Signer;
  network: HederaNetwork;
}

export interface AttestArgs {
  // The request and response the provider handled. Hashed with sha256 over
  // canonical JSON. Pass requestHash/responseHash directly to use your own
  // hashing instead; the caller's receipt must carry the same values.
  request?: unknown;
  response?: unknown;
  requestHash?: string;
  responseHash?: string;
  providerIssuedAt?: number;
}

// High-level provider co-signer. The two-line integration for an MCP server or
// any HTTP service: construct once with your identity and key, then call attest()
// with what you received and returned. Hand the result to the caller to anchor,
// or anchor it yourself.
export class HSealProvider {
  private readonly opts: HSealProviderOptions;

  constructor(opts: HSealProviderOptions) {
    this.opts = opts;
  }

  async attest(args: AttestArgs): Promise<ProviderAttestation> {
    const requestHash = args.requestHash ?? hashOrThrow("request", args.request);
    const responseHash = args.responseHash ?? hashOrThrow("response", args.response);
    return signProviderAttestation({
      attestation: {
        providerIdentity: this.opts.identity,
        requestHash,
        responseHash,
        ...(args.providerIssuedAt !== undefined ? { providerIssuedAt: args.providerIssuedAt } : {}),
      },
      signer: this.opts.signer,
      network: this.opts.network,
    });
  }
}

function hashOrThrow(label: string, value: unknown): string {
  if (value === undefined) {
    throw new Error(`attest requires either ${label} or ${label}Hash`);
  }
  return sha256Hex(value);
}
