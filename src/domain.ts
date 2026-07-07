import type { TypedDataField } from "ethers";

// Mirrors the constants in H-Seal's src/modules/tip712.ts. These define the
// EIP-712 domain and type sets the server verifies against; they are part of the
// wire contract, not local choices.

export type HederaNetwork = "mainnet" | "testnet";

export const HEDERA_CHAIN_ID: Record<HederaNetwork, number> = {
  mainnet: 295,
  testnet: 296,
};

export const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export interface Tip712Domain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: string;
}

export function buildDomain(chainId: number): Tip712Domain {
  return { name: "H-Seal", version: "1", chainId, verifyingContract: ZERO_ADDRESS };
}

// v0.1 receipt: the original 12 fields.
const ANCHOR_V1_FIELDS: TypedDataField[] = [
  { name: "taskId", type: "string" },
  { name: "serviceEndpoint", type: "string" },
  { name: "requestHash", type: "string" },
  { name: "responseHash", type: "string" },
  { name: "resultStatus", type: "string" },
  { name: "startedAt", type: "uint256" },
  { name: "completedAt", type: "uint256" },
  { name: "latencyMs", type: "uint256" },
  { name: "callerIdentity", type: "string" },
  { name: "providerIdentity", type: "string" },
  { name: "receiptTopicId", type: "string" },
  { name: "issuedAt", type: "uint256" },
];

// v0.2 adds method/httpStatus/correlationId/amount fields.
const ANCHOR_V2_EXTRA: TypedDataField[] = [
  { name: "schemaVersion", type: "uint256" },
  { name: "method", type: "string" },
  { name: "httpStatus", type: "uint256" },
  { name: "correlationId", type: "string" },
  { name: "amountPaid", type: "string" },
  { name: "amountCurrency", type: "string" },
];

const ANCHOR_V2_FIELDS: TypedDataField[] = [...ANCHOR_V1_FIELDS, ...ANCHOR_V2_EXTRA];

// v0.4 adds the chain-of-custody requestId on top of the v0.2 field set.
const ANCHOR_V4_FIELDS: TypedDataField[] = [...ANCHOR_V2_FIELDS, { name: "requestId", type: "string" }];

export const ANCHOR_RECEIPT_TYPES: Record<string, TypedDataField[]> = { AnchorReceipt: ANCHOR_V1_FIELDS };
export const ANCHOR_RECEIPT_TYPES_V2: Record<string, TypedDataField[]> = { AnchorReceipt: ANCHOR_V2_FIELDS };
export const ANCHOR_RECEIPT_TYPES_V4: Record<string, TypedDataField[]> = { AnchorReceipt: ANCHOR_V4_FIELDS };

// Provider co-signature over the subset a provider can compute from the bytes it
// actually exchanged.
export const PROVIDER_ATTEST_TYPES: Record<string, TypedDataField[]> = {
  ProviderAttestation: [
    { name: "providerIdentity", type: "string" },
    { name: "requestHash", type: "string" },
    { name: "responseHash", type: "string" },
    { name: "providerIssuedAt", type: "uint256" },
  ],
};
