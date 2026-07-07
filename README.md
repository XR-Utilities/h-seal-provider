# @xr-utilities/h-seal-provider

Drop-in client for signing and anchoring [H-Seal](https://h-seal.xr-utilities.com)
execution receipts. It lets an MCP server, or any HTTP service, co-sign the
receipts it serves and anchor them to Hedera Consensus Service.

H-Seal turns a request/response into a tamper-evident, independently verifiable
on-chain receipt. This SDK produces signatures byte-for-byte with what the H-Seal
service verifies, so a receipt you sign here anchors and re-verifies without a
round-trip through the service to "register" anything.

Supported chains: Hedera (Ed25519 and ECDSA), EVM (`eip155`, EIP-712), XRPL,
Solana, and Stellar. Identity is CAIP-10 (`hedera:mainnet:0.0.x`,
`eip155:8453:0x...`, `xrpl:0:r...`, `solana:mainnet:...`, `stellar:pubnet:G...`)
or a bare Hedera `0.0.x` account. For Stellar, build the Ed25519 signer from the
raw 32-byte seed decoded from your `S...` secret
(`StrKey.decodeEd25519SecretSeed` in `@stellar/stellar-sdk`); the signature is
verified against the `G...` account exactly like the Solana path.

## Install

This repo is public, so it installs straight from GitHub with no token and no
`.npmrc`:

```
npm install github:XR-Utilities/h-seal-provider
```

A git install builds from source on install (the `prepare` step runs `tsc`), so
you get `dist/` without a published tarball. Pin a release by ref when you want a
fixed version:

```
npm install github:XR-Utilities/h-seal-provider#v0.1.0
```

The package is also published to GitHub Packages as `@xr-utilities/h-seal-provider`
(private, versioned) for internal estate consumers; that path needs an
`@xr-utilities:registry=https://npm.pkg.github.com` entry in `.npmrc` and a
`read:packages` token. Use the public git install above when you want no token.

## Provider co-signing (the two-line integration)

You run an MCP server. After producing a response, co-sign the request/response
pair so the receipt the caller anchors carries your attestation that you served
it. The provider signs only what it can compute from the bytes it exchanged.

```ts
import { HSealProvider, ed25519Signer } from "@xr-utilities/h-seal-provider";

const provider = new HSealProvider({
  identity: "hedera:mainnet:0.0.7777",          // your provider account
  signer: ed25519Signer(process.env.PROVIDER_KEY_RAW!), // 32-byte ed25519 seed
  network: "mainnet",
});

// inside your tool handler, after you have the request and the response:
const attestation = await provider.attest({ request, response });
// hand `attestation` back to the caller, who attaches it to their receipt
```

`attest` hashes `request` and `response` with sha256 over canonical JSON. Pass
`requestHash` / `responseHash` directly if you hash them yourself; the caller's
receipt must carry the same values.

For an EVM or Hedera-ECDSA provider, swap the signer:

```ts
import { evmSigner } from "@xr-utilities/h-seal-provider";
const signer = evmSigner(process.env.PROVIDER_EVM_KEY!); // or an ethers Wallet
```

## Caller side: sign and anchor a receipt

```ts
import { signReceipt, attachAttestation, HSealClient, ed25519Signer } from "@xr-utilities/h-seal-provider";

const signed = await signReceipt({
  receipt: {
    taskId: "task-1",
    serviceEndpoint: "https://api.example.com/run",
    requestHash: "sha256:...",
    responseHash: "sha256:...",
    resultStatus: "success",
    startedAt, completedAt, latencyMs,
    callerIdentity: "hedera:mainnet:0.0.4242",
    providerIdentity: "hedera:mainnet:0.0.7777",
    receiptTopicId: "0.0.5555",          // the H-Seal receipt topic
  },
  signer: ed25519Signer(process.env.CALLER_KEY_RAW!),
  network: "mainnet",
});

const body = attachAttestation(signed.body, attestation); // optional provider co-sig

const client = new HSealClient({ endpoint: "https://h-seal.xr-utilities.com" });
const res = await client.anchor(body, { xPayment }); // xPayment from your x402 flow
// 201 -> { id, consensusTimestamp, paymentTxId, signatureScheme }
// 402 -> res.body carries the payment requirements to satisfy and retry
```

`schemaVersion` defaults to 4 when `requestId` is set, otherwise 2. Set it to 1
for a legacy receipt.

### OIDC identity privacy (what lands on chain)

When `callerIdentity` (or `providerIdentity`) is a wallet CAIP-10 value, it is anchored
raw, as shown above (already public on its own chain). When it is an enterprise OIDC
identity (`oidc:<issuer>:<subject>`, via the identity bridge), H-Seal anchors a
per-receipt salted commitment `sha256(identity||salt)` instead of the raw value, and the
operator co-attestation carries that same commitment (never the raw issuer/subject/jti).
The raw identity and the salt are stored off chain; the holder can later disclose the
`(identity, salt)` pair so an auditor recomputes and matches the on-chain commitment. So
an integrator passing an OIDC identity should not expect the raw IdP identity to be
readable on the receipt topic. This is distinct from the payment-commitment token below
(a single-use owner-bound payment authorization, not an identity hash).

### Sponsored (free) anchoring

A receipt co-signed by a provider the server has allowlisted anchors free: omit
`xPayment` and the provider co-signature stands in for payment. The provider
signature is verified on chain and locked single-use server-side.

## Payment-commitment placement (OIDC / cross-chain payers)

The default payment binding requires the on-chain payer to be the caller's own
same-chain account. Two cases cannot satisfy that and otherwise fail closed: an
OIDC caller (no wallet) and a cross-chain payment. For those, the 402 challenge
advertises `extra.paymentCommitment` - a single-use, owner-bound token you embed
in the on-chain payment so the server can bind it to this challenge.

This SDK does not build or sign the payment (it holds no payment keys); your
wallet does that. These helpers tell you exactly where the commitment goes for
your rail and hand back the ready-to-use value:

```ts
import { commitmentFromChallenge, placeCommitment } from "@xr-utilities/h-seal-provider";

const res = await client.anchor(body);            // no payment -> 402
const commitment = commitmentFromChallenge(res.body);
if (commitment) {
  const place = placeCommitment(commitment, "solana-mainnet-sol"); // your rail label
  // place.carrier tells you how to attach it:
  //   "memo-hex"          Hedera / Solana  -> set the tx memo to place.hex
  //   "xrpl-memo"         XRPL             -> Memos[].Memo.MemoData = place.hex
  //   "stellar-memo-hash" Stellar          -> Memo.hash(place.bytes)   (32 bytes)
  //   "evm-eip3009-nonce" EVM (USDC)       -> EIP-3009 nonce = place.nonce (bytes32)
  //   "none"              no carrier on this rail (plain EVM/Stellar-USDC transfer)
}
// ...build + submit the payment with your wallet, embedding the value above, then:
const ok = await client.anchor(body, { xPayment }); // 201
```

Per-carrier primitives (`commitmentMemoText`, `commitmentXrplMemoData`,
`commitmentStellarMemoHash`, `commitmentEvmNonce`) are exported too when you know
your rail up front.

> Roadmap: a full "pay-and-anchor" flow - the SDK builds, signs, and submits the
> on-chain payment for you across all rails (a wallet/RPC integration per chain),
> so OIDC/cross-chain payment is one call. Today the SDK stays a signer +
> transport library and hands you the placement; your wallet builds the payment.

## Re-verify a receipt you already hold

```ts
const verdict = await client.verify(body);
// { ok: true, scheme: "ED25519", provider?: { ok, scheme } }
```

No payment, no state change. Answers "does this signature verify against this
identity's on-chain key?".

## Bring your own key store

`ed25519Signer` and `evmSigner` are conveniences. For KMS or a hardware signer,
implement the `Ed25519Signer` or `EvmSigner` interface directly; the SDK only
needs the signing primitive and (for ed25519) the raw public key.

## Hashing

`sha256Hex(value)` is the convention for `requestHash` / `responseHash`: sha256
over canonical JSON for objects, or over raw bytes for a string/Buffer, prefixed
`sha256:`. The server does not interpret these strings; the caller and provider
just need to agree.
