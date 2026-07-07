import type { TypedDataField } from "ethers";
import { buildDomain } from "./domain.js";
import { hashCanonicalJson } from "./canonical.js";
import type { ParsedIdentity } from "./identity.js";
import type { Signer } from "./signers.js";

// Everything a single signature needs: the canonical-JSON preimage parts
// (kind + payload) for the ed25519 chains, and the EIP-712 type set + message
// for EVM/Hedera-ECDSA. Built once by the receipt/attestation layer, signed here.
export interface SignSpec {
  kind: string;
  payload: unknown;
  eip712Types: Record<string, TypedDataField[]>;
  eip712Message: Record<string, unknown>;
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

// The Hedera "signed message" envelope the mirror-backed verifier reconstructs:
// 0x19 + "Hedera Signed Message:\n" + len + hexDigest, signed as ed25519.
function hederaPrefixedMessage(digestHex: string): Buffer {
  const prefixed = `\x19Hedera Signed Message:\n${digestHex.length}${digestHex}`;
  return Buffer.from(prefixed, "utf-8");
}

// Produce the wire signature string for one identity. Dispatches on the signer
// shape and the identity namespace exactly the way H-Seal's dispatchVerify does
// in reverse, so the output verifies under the matching server path.
export async function signFor(
  identity: ParsedIdentity,
  signer: Signer,
  spec: SignSpec,
): Promise<string> {
  if (signer.kind === "evm") {
    if (identity.namespace !== "eip155" && identity.namespace !== "hedera") {
      throw new Error(`EVM signer cannot sign for namespace ${identity.namespace}`);
    }
    const domain = buildDomain(identity.evmChainId);
    return signer.signTypedData(domain, spec.eip712Types, spec.eip712Message);
  }

  // ed25519: Hedera-Ed25519, XRPL, and Solana share the primitive but differ in
  // what bytes are signed and how the signature is framed on the wire.
  const digest = hashCanonicalJson({ kind: spec.kind, payload: spec.payload });

  if (identity.namespace === "hedera") {
    const msg = hederaPrefixedMessage(digest.toString("hex"));
    const sig = await signer.sign(msg);
    return toHex(sig);
  }

  if (identity.namespace === "xrpl") {
    // XRPL signs the raw 32-byte digest; the wire form is pubkey_hex:signature_hex
    // with the 0xED ed25519 prefix the server uses to derive and check the r-address.
    const sig = await signer.sign(digest);
    const pubKeyHex = `ed${toHex(signer.publicKeyRaw())}`;
    return `${pubKeyHex}:${toHex(sig)}`;
  }

  if (identity.namespace === "solana") {
    // Solana signs the raw digest; the server accepts that or the canonical text.
    const sig = await signer.sign(digest);
    return toHex(sig);
  }

  if (identity.namespace === "stellar") {
    // Stellar (G... account) signs the raw digest, mirroring Solana; H-Seal's
    // verifyStellarDirect accepts a signature over the digest or the canonical
    // text. The wire form is the 64-byte ed25519 signature in hex.
    const sig = await signer.sign(digest);
    return toHex(sig);
  }

  throw new Error(`ed25519 signer cannot sign for namespace ${identity.namespace}`);
}
