import type { TypedDataField } from "ethers";
import {
  ANCHOR_RECEIPT_TYPES,
  ANCHOR_RECEIPT_TYPES_V2,
  ANCHOR_RECEIPT_TYPES_V4,
  type HederaNetwork,
} from "./domain.js";
import { parseIdentity, nowSeconds } from "./identity.js";
import { signFor } from "./sign-core.js";
import type { Signer } from "./signers.js";

export type ResultStatus = "success" | "error" | "timeout" | "partial";

// Caller-facing receipt fields. Optional fields default the way the H-Seal route
// defaults them, so the signed payload matches the server's reconstruction.
export interface ReceiptInput {
  taskId: string;
  serviceEndpoint: string;
  requestHash: string;
  responseHash: string;
  resultStatus: ResultStatus;
  startedAt: number;
  completedAt: number;
  latencyMs: number;
  callerIdentity: string;
  providerIdentity?: string;
  receiptTopicId: string;
  issuedAt?: number;
  method?: string;
  httpStatus?: number;
  correlationId?: string;
  amountPaid?: string;
  amountCurrency?: string;
  requestId?: string;
  // Defaults to 4 when requestId is present, else 2. Set 1 for a legacy receipt.
  schemaVersion?: number;
}

// The flat object POSTed to H-Seal's /anchor route.
export interface AnchorRequestBody {
  taskId: string;
  serviceEndpoint: string;
  requestHash: string;
  responseHash: string;
  resultStatus: ResultStatus;
  startedAt: number;
  completedAt: number;
  latencyMs: number;
  callerIdentity: string;
  providerIdentity: string;
  receiptTopicId: string;
  issuedAt: number;
  signature: string;
  schemaVersion?: number;
  method?: string;
  httpStatus?: number;
  correlationId?: string;
  amountPaid?: string;
  amountCurrency?: string;
  requestId?: string;
  providerSignature?: string;
  providerSignatureScheme?: string;
  providerIssuedAt?: number;
  xPayment?: string;
}

export interface SignedReceipt {
  body: AnchorRequestBody;
  signature: string;
  schemaVersion: number;
}

interface PayloadBuild {
  // Canonical-JSON preimage (ed25519 chains): exactly the fields the route
  // reconstructs at this schemaVersion.
  payload: Record<string, unknown>;
  // EIP-712 type set + message (EVM / Hedera-ECDSA).
  types: Record<string, TypedDataField[]>;
  message: Record<string, unknown>;
  schemaVersion: number;
  issuedAt: number;
  providerIdentity: string;
}

function resolveSchemaVersion(r: ReceiptInput): number {
  if (r.schemaVersion !== undefined) return r.schemaVersion;
  return r.requestId !== undefined ? 4 : 2;
}

// Build the signed payload and the EIP-712 view, mirroring the route's payload
// assembly and tip712's eip712TypeAndMessage so both signing paths reconstruct
// to the same digest the server checks.
function buildPayload(r: ReceiptInput): PayloadBuild {
  const schemaVersion = resolveSchemaVersion(r);
  const issuedAt = r.issuedAt ?? nowSeconds();
  const providerIdentity = r.providerIdentity ?? "";

  const base: Record<string, unknown> = {
    taskId: r.taskId,
    serviceEndpoint: r.serviceEndpoint,
    requestHash: r.requestHash,
    responseHash: r.responseHash,
    resultStatus: r.resultStatus,
    startedAt: r.startedAt,
    completedAt: r.completedAt,
    latencyMs: r.latencyMs,
    callerIdentity: r.callerIdentity,
    providerIdentity,
    receiptTopicId: r.receiptTopicId,
    issuedAt,
  };

  const v2Block = {
    schemaVersion,
    method: r.method ?? "",
    httpStatus: r.httpStatus ?? 0,
    correlationId: r.correlationId ?? "",
    amountPaid: r.amountPaid ?? "",
    amountCurrency: r.amountCurrency ?? "",
  };

  const payload: Record<string, unknown> = { ...base };
  if (schemaVersion >= 2) Object.assign(payload, v2Block);
  if (schemaVersion === 4) payload.requestId = r.requestId ?? "";

  // EIP-712 view: V2/V4 use the explicit field set with defaults; everything else
  // (v1, and the v3 provider-cosign case) uses the V1 type set over the payload.
  if (schemaVersion === 2 || schemaVersion === 4) {
    const v2Message = { ...base, ...v2Block };
    if (schemaVersion === 4) {
      return {
        payload,
        types: ANCHOR_RECEIPT_TYPES_V4,
        message: { ...v2Message, requestId: r.requestId ?? "" },
        schemaVersion,
        issuedAt,
        providerIdentity,
      };
    }
    return { payload, types: ANCHOR_RECEIPT_TYPES_V2, message: v2Message, schemaVersion, issuedAt, providerIdentity };
  }
  return { payload, types: ANCHOR_RECEIPT_TYPES, message: payload, schemaVersion, issuedAt, providerIdentity };
}

export interface SignReceiptOptions {
  receipt: ReceiptInput;
  signer: Signer;
  network: HederaNetwork;
}

// Sign a receipt as the caller and return the ready-to-POST anchor body.
export async function signReceipt(opts: SignReceiptOptions): Promise<SignedReceipt> {
  const { receipt, signer, network } = opts;
  const built = buildPayload(receipt);
  const identity = parseIdentity(receipt.callerIdentity, network);

  const signature = await signFor(identity, signer, {
    kind: "anchor",
    payload: built.payload,
    eip712Types: built.types,
    eip712Message: built.message,
  });

  const body: AnchorRequestBody = {
    taskId: receipt.taskId,
    serviceEndpoint: receipt.serviceEndpoint,
    requestHash: receipt.requestHash,
    responseHash: receipt.responseHash,
    resultStatus: receipt.resultStatus,
    startedAt: receipt.startedAt,
    completedAt: receipt.completedAt,
    latencyMs: receipt.latencyMs,
    callerIdentity: receipt.callerIdentity,
    providerIdentity: built.providerIdentity,
    receiptTopicId: receipt.receiptTopicId,
    issuedAt: built.issuedAt,
    signature,
  };
  if (built.schemaVersion >= 2) {
    body.schemaVersion = built.schemaVersion;
    body.method = receipt.method ?? "";
    body.httpStatus = receipt.httpStatus ?? 0;
    body.correlationId = receipt.correlationId ?? "";
    body.amountPaid = receipt.amountPaid ?? "";
    body.amountCurrency = receipt.amountCurrency ?? "";
  }
  if (built.schemaVersion === 4) body.requestId = receipt.requestId ?? "";

  return { body, signature, schemaVersion: built.schemaVersion };
}
