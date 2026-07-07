// @xr-utilities/h-seal-provider
//
// Sign and anchor H-Seal execution receipts. The signing output is byte-exact
// with what the H-Seal service verifies (src/modules/tip712.ts): Hedera-Ed25519,
// EVM/Hedera-ECDSA EIP-712, XRPL, and Solana.

export { canonicalJson, hashCanonicalJson, sha256, sha256Hex } from "./canonical.js";
export {
  HEDERA_CHAIN_ID,
  buildDomain,
  ANCHOR_RECEIPT_TYPES,
  ANCHOR_RECEIPT_TYPES_V2,
  ANCHOR_RECEIPT_TYPES_V4,
  PROVIDER_ATTEST_TYPES,
  ZERO_ADDRESS,
  type HederaNetwork,
  type Tip712Domain,
} from "./domain.js";
export {
  parseIdentity,
  nowSeconds,
  type Namespace,
  type ParsedIdentity,
} from "./identity.js";
export {
  ed25519Signer,
  evmSigner,
  generateEd25519,
  type Signer,
  type Ed25519Signer,
  type EvmSigner,
} from "./signers.js";
export {
  signReceipt,
  type ReceiptInput,
  type ResultStatus,
  type AnchorRequestBody,
  type SignedReceipt,
} from "./receipt.js";
export {
  signProviderAttestation,
  attachAttestation,
  type ProviderAttestation,
  type ProviderAttestationInput,
  type SignProviderAttestationOptions,
} from "./attestation.js";
export {
  HSealClient,
  type HSealClientOptions,
  type AnchorResponse,
  type VerifyResponse,
} from "./client.js";
export {
  HSealProvider,
  type HSealProviderOptions,
  type AttestArgs,
} from "./provider.js";
export {
  commitmentFromChallenge,
  normalizeCommitment,
  placeCommitment,
  commitmentMemoText,
  commitmentXrplMemoData,
  commitmentStellarMemoHash,
  commitmentEvmNonce,
  type CommitmentCarrier,
  type CommitmentPlacement,
} from "./commitment.js";
