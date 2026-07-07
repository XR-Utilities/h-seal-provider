#!/usr/bin/env node
// H-Seal signing sidecar, shipped as a bin of the SDK so a non-Node service (a
// Python/FastAPI backend, say) can co-sign receipts with the exact SDK over HTTP.
// Written with node:http only, so it adds ZERO dependencies to the library.
//
//   npx -p github:XR-Utilities/h-seal-provider hseal-sidecar
//
// Env: PROVIDER_IDENTITY, PROVIDER_KEY_RAW (32-byte ed25519 hex, or an EVM key with
// PROVIDER_KEY_TYPE=evm), HSEAL_NETWORK (mainnet|testnet), SIDECAR_AUTH_TOKEN
// (optional bearer), HOST (default 0.0.0.0), PORT (default 8791).
//
// PROXY MODE (turnkey, zero code in the service): set PROXY_TARGET to your service's
// base URL. The sidecar then forwards every non-reserved request to it, co-signs the
// {request, response} pair, and returns the response with the attestation in the
// `x-hseal-attestation` header (base64 JSON) plus, for a JSON object response, a
// `_hSeal` field. Route your service's traffic through the sidecar and every response
// is signed by the service's identity, no handler changes. For request/response JSON
// APIs (streaming/SSE is passed through unsigned).
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { HSealProvider, ed25519Signer, evmSigner, signReceipt, type Signer } from "./index.js";

const env = process.env;
const NETWORK = (env.HSEAL_NETWORK ?? "mainnet") as "mainnet" | "testnet";
const AUTH = env.SIDECAR_AUTH_TOKEN ?? "";
const HOST = env.HOST ?? "0.0.0.0";
const PORT = Number(env.PORT ?? 8791);
const PROXY_TARGET = (env.PROXY_TARGET ?? "").replace(/\/+$/, "");

function buildSigner(): Signer | null {
  if (!env.PROVIDER_KEY_RAW) return null;
  return (env.PROVIDER_KEY_TYPE ?? "ed25519") === "evm"
    ? evmSigner(env.PROVIDER_KEY_RAW)
    : ed25519Signer(env.PROVIDER_KEY_RAW);
}

const signer = buildSigner();
const identity = env.PROVIDER_IDENTITY ?? "";
const provider =
  identity && signer ? new HSealProvider({ identity, signer, network: NETWORK }) : null;

if (!provider)
  console.warn(
    "[hseal-sidecar] provider unset (PROVIDER_IDENTITY / PROVIDER_KEY_RAW) - /attest and /sign-receipt return 503 until configured",
  );
if (!AUTH)
  console.warn(
    "[hseal-sidecar] SIDECAR_AUTH_TOKEN unset - signing endpoints are UNAUTHENTICATED; run on a private network or localhost, or set the token",
  );

function authed(req: IncomingMessage): boolean {
  if (!AUTH) return true;
  const hdr = req.headers["authorization"] ?? "";
  const tok = hdr.startsWith("Bearer ") ? hdr.slice(7) : "";
  const a = Buffer.from(tok);
  const b = Buffer.from(AUTH);
  return a.length === b.length && timingSafeEqual(a, b);
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json" });
  res.end(payload);
}

function readJson(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let raw = "";
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > 256 * 1024) reject(new Error("body too large"));
      else raw += c;
    });
    req.on("end", () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error("invalid json"));
      }
    });
    req.on("error", reject);
  });
}

function readRaw(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let raw = "";
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > 1024 * 1024) reject(new Error("body too large"));
      else raw += c;
    });
    req.on("end", () => resolve(raw));
    req.on("error", reject);
  });
}

function tryParse(s: string): unknown {
  try {
    return s ? JSON.parse(s) : {};
  } catch {
    return null;
  }
}

// Turnkey signing proxy: forward the request to PROXY_TARGET, co-sign the
// {request, response} pair, and return the response augmented with the attestation.
// Transparent (unsigned) pass-through if the provider is unset or the target errors,
// so wiring the proxy never breaks the underlying service.
async function proxy(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const path = req.url ?? "/";
  const method = req.method ?? "GET";
  const reqBody = method === "GET" || method === "HEAD" ? "" : await readRaw(req).catch(() => "");

  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const key = k.toLowerCase();
    if (key === "host" || key === "content-length" || key === "connection") continue;
    if (typeof v === "string") headers[k] = v;
  }

  let upstream: Response;
  try {
    upstream = await fetch(`${PROXY_TARGET}${path}`, {
      method,
      headers,
      body: reqBody ? reqBody : undefined,
    });
  } catch (e) {
    return send(res, 502, { error: "proxy target unreachable", detail: String((e as Error).message).slice(0, 120) });
  }

  const respText = await upstream.text();
  const respType = upstream.headers.get("content-type") ?? "application/json";
  const respJson = respType.includes("json") ? tryParse(respText) : null;

  // Attest over the request/response pair. Only when the provider is configured and
  // the response parsed as JSON (the co-sign model hashes canonical JSON).
  let attestation: unknown = null;
  if (provider && respJson !== null) {
    try {
      const requestForSig = tryParse(reqBody) ?? { method, path };
      attestation = await provider.attest({ request: requestForSig, response: respJson });
    } catch (e) {
      console.error("[hseal-sidecar] proxy attest failed", (e as Error).message);
    }
  }

  // Return the upstream response, augmented with the attestation.
  const outHeaders: Record<string, string> = { "content-type": respType };
  let outBody = respText;
  if (attestation) {
    outHeaders["x-hseal-attestation"] = Buffer.from(JSON.stringify(attestation)).toString("base64");
    if (respJson !== null && typeof respJson === "object" && !Array.isArray(respJson)) {
      outBody = JSON.stringify({ ...(respJson as Record<string, unknown>), _hSeal: attestation });
    }
  }
  res.writeHead(upstream.status, outHeaders);
  res.end(outBody);
}

const server = createServer(async (req, res) => {
  const url = req.url ?? "/";
  const method = req.method ?? "GET";

  if (method === "GET" && url === "/health") {
    return send(res, 200, {
      status: "ok",
      service: "hseal-sidecar",
      configured: Boolean(provider),
      network: NETWORK,
      authRequired: Boolean(AUTH),
    });
  }

  if (method === "POST" && (url === "/attest" || url === "/sign-receipt")) {
    if (!authed(req)) return send(res, 401, { error: "unauthorized" });

    let body: Record<string, unknown>;
    try {
      body = (await readJson(req)) as Record<string, unknown>;
    } catch (e) {
      return send(res, 400, { error: (e as Error).message });
    }

    if (url === "/attest") {
      if (!provider) return send(res, 503, { error: "provider not configured" });
      if (!("request" in body) || !("response" in body))
        return send(res, 400, { error: "body must be { request, response }" });
      try {
        const attestation = await provider.attest({
          request: body.request,
          response: body.response,
        });
        return send(res, 200, attestation);
      } catch (e) {
        console.error("[hseal-sidecar] attest failed", (e as Error).message);
        return send(res, 400, { error: "attest failed" });
      }
    }

    // /sign-receipt
    if (!signer) return send(res, 503, { error: "signer not configured" });
    if (typeof body.receipt !== "object" || body.receipt === null)
      return send(res, 400, { error: "body must be { receipt }" });
    try {
      const signed = await signReceipt({ receipt: body.receipt as never, signer, network: NETWORK });
      return send(res, 200, signed.body);
    } catch (e) {
      console.error("[hseal-sidecar] sign-receipt failed", (e as Error).message);
      return send(res, 400, { error: "sign failed", reason: String((e as Error).message).slice(0, 200) });
    }
  }

  // Everything else: proxy to the target and sign the response, when proxy mode is on.
  if (PROXY_TARGET) return proxy(req, res);

  return send(res, 404, { error: "not found" });
});

if (PROXY_TARGET)
  console.log(`[hseal-sidecar] proxy mode -> ${PROXY_TARGET} (every response signed by ${identity || "<unset>"})`);

server.listen(PORT, HOST, () => {
  console.log(
    `[hseal-sidecar] listening on ${HOST}:${PORT} (configured=${Boolean(provider)}, auth=${Boolean(AUTH)}, network=${NETWORK}, proxy=${Boolean(PROXY_TARGET)})`,
  );
});
