import type { AnchorRequestBody } from "./receipt.js";

export interface HSealClientOptions {
  // Base URL of the H-Seal service, e.g. https://h-seal.xr-utilities.com.
  endpoint: string;
  // Injectable for tests; defaults to the global fetch (Node 20+).
  fetchImpl?: typeof fetch;
}

export interface AnchorResponse {
  status: number;
  ok: boolean;
  // Parsed JSON body. On 201: { id, consensusTimestamp, paymentTxId, signatureScheme }.
  // On 402: the x402 payment-required body. On 4xx/5xx: { error, ... }.
  body: unknown;
}

export interface VerifyResponse {
  status: number;
  ok: boolean;
  scheme?: string;
  reason?: string;
  provider?: { ok: boolean; scheme?: string; reason?: string };
  recipient?: { ok: boolean; scheme?: string; reason?: string };
}

function joinUrl(base: string, path: string): string {
  return `${base.replace(/\/+$/, "")}${path}`;
}

// Thin transport over the H-Seal HTTP API. It does not hold keys or sign; it
// carries already-signed bodies to /anchor and /verify.
export class HSealClient {
  private readonly endpoint: string;
  private readonly fetchImpl: typeof fetch;

  constructor(opts: HSealClientOptions) {
    this.endpoint = opts.endpoint;
    this.fetchImpl = opts.fetchImpl ?? fetch;
  }

  // Anchor a signed receipt. Pass xPayment (an x402 payment header value) for the
  // paid path; omit it for the sponsored/free path, in which case a 402 response
  // carries the payment requirements to satisfy and retry.
  async anchor(body: AnchorRequestBody, opts: { xPayment?: string } = {}): Promise<AnchorResponse> {
    const headers: Record<string, string> = { "content-type": "application/json" };
    const xPayment = opts.xPayment ?? body.xPayment;
    if (xPayment) headers["x-payment"] = xPayment;

    const res = await this.fetchImpl(joinUrl(this.endpoint, "/anchor"), {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    const parsed = await res.json().catch(() => null);
    return { status: res.status, ok: res.ok, body: parsed };
  }

  // Re-verify a receipt the caller already holds against on-chain keys. No
  // payment, no state change. Returns the server's verdict.
  async verify(body: AnchorRequestBody): Promise<VerifyResponse> {
    const res = await this.fetchImpl(joinUrl(this.endpoint, "/verify"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const parsed = (await res.json().catch(() => ({}))) as Omit<VerifyResponse, "status" | "ok">;
    return { status: res.status, ...parsed } as VerifyResponse;
  }
}
