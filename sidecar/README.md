# hseal-sidecar

An HTTP signing sidecar over [`@xr-utilities/h-seal-provider`](../README.md). It
lets a service that is **not** Node/TypeScript (a Python/FastAPI backend, say)
produce H-Seal receipt signatures with the exact SDK, so signatures always verify
byte-for-byte and you never port the signing/canonicalization logic.

Why a sidecar: co-signing at a gateway (an MCP passthrough) attests "this was
relayed." Calling the sidecar from the service that did the work makes the receipt
attest to **what the backend actually computed**. One small Node process, any
number of non-Node callers.

It lives in the SDK repo (one home, always in step with the SDK) but is a separate
deployable: the repo root stays a clean, dependency-light library, and the
sidecar's server deps live only here.

## Run

```bash
cd sidecar
cp .env.example .env      # fill PROVIDER_IDENTITY + PROVIDER_KEY_RAW
npm install               # pulls the SDK from its public git tag
npm run build && npm start
# or: npm run dev
```

Or with Docker (self-contained, build from this directory):

```bash
docker build -t hseal-sidecar sidecar/
docker run -p 8791:8791 --env-file sidecar/.env hseal-sidecar
```

Unset provider env leaves the signing endpoints returning `503` (inert by design).

## Endpoints

- `GET /health` -> `{ status, configured, network, authRequired }`
- `POST /attest` `{ request, response }` -> the provider attestation
  (`providerIdentity`, `providerSignature`, `providerSignatureScheme`,
  `requestHash`, `responseHash`). Attach it to the receipt the caller anchors.
- `POST /sign-receipt` `{ receipt }` -> the signed receipt body (the caller then
  anchors it to H-Seal itself). The sidecar signs only; it never anchors or holds funds.

When `SIDECAR_AUTH_TOKEN` is set, `/attest` and `/sign-receipt` require
`Authorization: Bearer <token>`.

## Call it from Python (FastAPI)

```python
import httpx

async def h_seal_attest(request: dict, response: dict) -> dict:
    async with httpx.AsyncClient() as client:
        r = await client.post(
            "http://hseal-sidecar:8791/attest",
            json={"request": request, "response": response},
            headers={"Authorization": f"Bearer {SIDECAR_TOKEN}"},  # if configured
            timeout=5.0,
        )
        r.raise_for_status()
        return r.json()   # attach to the receipt you anchor
```

## Key type note (read before setting env)

For an `xrpl:0:r...` identity the account **must be ed25519**: the H-Seal server
derives and checks the r-address from the `0xED` ed25519 pubkey, so a default
secp256k1 XRPL account will not verify. Generate the wallet as ed25519, or use a
`hedera:mainnet:0.0.x` ed25519 key for the provider (simplest; receipts anchor to
Hedera regardless).

## Deploy note

The sidecar pins the SDK by git tag (`#v0.1.0`). On a new SDK release, bump that
pin in `package.json` and redeploy.
