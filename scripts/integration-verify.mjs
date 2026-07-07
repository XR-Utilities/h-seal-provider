// Live check against a running H-Seal: sign a receipt with this SDK and POST it
// to /verify (read-only, no payment, no state change). A green verdict proves the
// live server accepts signatures this SDK produces.
//
// Run after `npm run build`:
//   H_SEAL_URL=https://h-seal.xr-utilities.com \
//   NETWORK=mainnet \
//   CALLER_IDENTITY=hedera:mainnet:0.0.4242 \
//   CALLER_KEY_RAW=<32-byte ed25519 seed hex> \
//   RECEIPT_TOPIC_ID=0.0.5555 \
//   node scripts/integration-verify.mjs
//
// For an EVM caller, set CALLER_EVM_KEY=<0x hex> instead of CALLER_KEY_RAW and
// use an eip155 CALLER_IDENTITY.

import { signReceipt, ed25519Signer, evmSigner, HSealClient, nowSeconds } from "../dist/index.js";

function required(name) {
  const v = process.env[name];
  if (!v) throw new Error(`missing env ${name}`);
  return v;
}

const endpoint = required("H_SEAL_URL");
const network = process.env.NETWORK === "testnet" ? "testnet" : "mainnet";
const callerIdentity = required("CALLER_IDENTITY");
const receiptTopicId = required("RECEIPT_TOPIC_ID");

const signer = process.env.CALLER_EVM_KEY
  ? evmSigner(process.env.CALLER_EVM_KEY)
  : ed25519Signer(required("CALLER_KEY_RAW"));

const now = nowSeconds();
const signed = await signReceipt({
  receipt: {
    taskId: `integration-${now}`,
    serviceEndpoint: "https://example.com/run",
    requestHash: "sha256:00",
    responseHash: "sha256:11",
    resultStatus: "success",
    startedAt: now - 2,
    completedAt: now - 1,
    latencyMs: 1000,
    callerIdentity,
    receiptTopicId,
    issuedAt: now,
    method: "POST",
    httpStatus: 200,
  },
  signer,
  network,
});

const client = new HSealClient({ endpoint });
const verdict = await client.verify(signed.body);

process.stdout.write(`${JSON.stringify(verdict, null, 2)}\n`);
if (!verdict.ok) {
  process.stderr.write("verification FAILED\n");
  process.exit(1);
}
process.stdout.write("verification OK: the live H-Seal accepts this SDK's signatures\n");
