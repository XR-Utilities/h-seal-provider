import { serve } from "@hono/node-server";
import { Hono, type Context, type Next } from "hono";
import { timingSafeEqual } from "node:crypto";
import { z } from "zod";
import {
  HSealProvider,
  ed25519Signer,
  evmSigner,
  signReceipt,
  type Signer,
} from "@xr-utilities/h-seal-provider";

// HTTP signing sidecar over the H-Seal SDK. A non-Node service (e.g. a Python
// FastAPI backend) POSTs the request/response it actually served and gets back a
// provider co-signature, so the receipt attests to what the BACKEND computed,
// not just what a gateway relayed. The provider key never leaves this process.

const env = process.env;
const NETWORK = (env.HSEAL_NETWORK ?? "mainnet") as "mainnet" | "testnet";
const AUTH = env.SIDECAR_AUTH_TOKEN ?? "";
const PORT = Number(env.PORT ?? 8791);

// Signer from env only; ed25519 (Hedera/XRPL/Solana/Stellar) or evm. For an
// xrpl:0:r... identity the account MUST be ed25519 (the H-Seal server derives the
// r-address from the 0xED ed25519 pubkey; a secp256k1 XRPL account will not verify).
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
    "[hseal-sidecar] SIDECAR_AUTH_TOKEN unset - signing endpoints are UNAUTHENTICATED; run only on a private network or localhost",
  );

// The provider key vouches for whatever content it signs, so gate the signing
// endpoints behind a shared secret when one is set (constant-time compare).
function authGate(c: Context, next: Next) {
  if (!AUTH) return next();
  const hdr = c.req.header("authorization") ?? "";
  const tok = hdr.startsWith("Bearer ") ? hdr.slice(7) : "";
  const a = Buffer.from(tok);
  const b = Buffer.from(AUTH);
  if (a.length !== b.length || !timingSafeEqual(a, b))
    return c.json({ error: "unauthorized" }, 401);
  return next();
}

const AttestBody = z
  .object({ request: z.unknown(), response: z.unknown() })
  .refine((o) => o.request !== undefined && o.response !== undefined, {
    message: "request and response are required",
  });

const ReceiptBody = z.object({ receipt: z.record(z.unknown()) });

const app = new Hono();

app.get("/health", (c) =>
  c.json({
    status: "ok",
    service: "hseal-sidecar",
    configured: Boolean(provider),
    network: NETWORK,
    authRequired: Boolean(AUTH),
  }),
);

// Co-sign a request/response pair: returns the H-Seal provider attestation the
// caller attaches to its receipt (providerIdentity, providerSignature, hashes).
app.post("/attest", authGate, async (c) => {
  if (!provider) return c.json({ error: "provider not configured" }, 503);
  let body: z.infer<typeof AttestBody>;
  try {
    body = AttestBody.parse(await c.req.json());
  } catch {
    return c.json({ error: "invalid body: { request, response } required" }, 400);
  }
  try {
    const attestation = await provider.attest({ request: body.request, response: body.response });
    return c.json(attestation);
  } catch (e) {
    console.error("[hseal-sidecar] attest failed", (e as Error).message);
    return c.json({ error: "attest failed" }, 400);
  }
});

// Sign a full receipt (caller side). The caller anchors the returned body to
// H-Seal itself; the sidecar only signs, it never anchors or holds funds.
app.post("/sign-receipt", authGate, async (c) => {
  if (!signer) return c.json({ error: "signer not configured" }, 503);
  let body: z.infer<typeof ReceiptBody>;
  try {
    body = ReceiptBody.parse(await c.req.json());
  } catch {
    return c.json({ error: "invalid body: { receipt } required" }, 400);
  }
  try {
    // The SDK validates the receipt shape and throws a descriptive error on a bad
    // field; surface a short, first-party reason (the SDK's own message, no upstream body).
    const signed = await signReceipt({ receipt: body.receipt as never, signer, network: NETWORK });
    return c.json(signed.body);
  } catch (e) {
    console.error("[hseal-sidecar] sign-receipt failed", (e as Error).message);
    return c.json({ error: "sign failed", reason: String((e as Error).message).slice(0, 200) }, 400);
  }
});

serve({ fetch: app.fetch, port: PORT });
console.log(
  `[hseal-sidecar] listening on :${PORT} (configured=${Boolean(provider)}, auth=${Boolean(AUTH)}, network=${NETWORK})`,
);
