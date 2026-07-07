import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  type KeyObject,
} from "node:crypto";
import { Wallet, type TypedDataDomain, type TypedDataField } from "ethers";

// Two signer shapes cover every chain H-Seal verifies. Ed25519 is the raw
// 64-byte primitive shared by Hedera-Ed25519, XRPL, Solana, and Stellar (the SDK
// formats the message and the signature envelope per chain). EVM/Hedera-ECDSA sign
// EIP-712 typed data, which is not a raw byte signature, so it gets its own
// shape. Both are async-friendly so a KMS-backed implementation can satisfy them.

export interface Ed25519Signer {
  readonly kind: "ed25519";
  // The 32-byte raw public key. Needed to build the XRPL pubkey envelope and to
  // let callers sanity-check the identity address derives from this key.
  publicKeyRaw(): Uint8Array;
  sign(message: Uint8Array): Promise<Uint8Array> | Uint8Array;
}

export interface EvmSigner {
  readonly kind: "evm";
  // Checksummed address the recovered EIP-712 signer must match.
  readonly address: string;
  signTypedData(
    domain: TypedDataDomain,
    types: Record<string, TypedDataField[]>,
    message: Record<string, unknown>,
  ): Promise<string>;
}

export type Signer = Ed25519Signer | EvmSigner;

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function rawSeedToPrivateKey(seed: Buffer): KeyObject {
  if (seed.length !== 32) {
    throw new Error(`ed25519 seed must be 32 bytes, got ${seed.length}`);
  }
  const pkcs8 = Buffer.concat([PKCS8_ED25519_PREFIX, seed]);
  return createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
}

function rawPublicKey(privateKey: KeyObject): Buffer {
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" }) as Buffer;
  // SPKI for ed25519 is a fixed 12-byte header followed by the 32-byte key.
  return spki.subarray(spki.length - 32);
}

// Build an Ed25519 signer from a 32-byte raw seed (hex string or Buffer) or from
// a Node KeyObject. For Hedera, pass the private key's raw bytes
// (PrivateKey.toStringRaw() from @hiero-ledger/sdk). For XRPL/Solana pass the
// 32-byte ed25519 seed whose public key derives to the account address. For
// Stellar, pass the raw seed decoded from the S... secret
// (StrKey.decodeEd25519SecretSeed from @stellar/stellar-sdk).
export function ed25519Signer(key: string | Buffer | Uint8Array | KeyObject): Ed25519Signer {
  let privateKey: KeyObject;
  if (typeof key === "string") {
    const hex = key.startsWith("0x") ? key.slice(2) : key;
    privateKey = rawSeedToPrivateKey(Buffer.from(hex, "hex"));
  } else if (key instanceof Buffer || key instanceof Uint8Array) {
    privateKey = rawSeedToPrivateKey(Buffer.from(key));
  } else {
    privateKey = key;
  }
  const pub = rawPublicKey(privateKey);
  return {
    kind: "ed25519",
    publicKeyRaw: () => pub,
    sign: (message: Uint8Array) => nodeSign(null, Buffer.from(message), privateKey),
  };
}

// Build an EVM signer from an ethers Wallet or a hex private key. Used for
// eip155 callers and for Hedera accounts whose key is ECDSA_SECP256K1.
export function evmSigner(wallet: Wallet | string): EvmSigner {
  const w = typeof wallet === "string" ? new Wallet(wallet) : wallet;
  return {
    kind: "evm",
    address: w.address,
    signTypedData: (domain, types, message) => w.signTypedData(domain, types, message),
  };
}

// Generate a fresh Ed25519 keypair (raw seed + signer). Useful for tests and for
// bootstrapping a provider key in a non-production setting.
export function generateEd25519(): { seed: Buffer; publicKeyRaw: Buffer; signer: Ed25519Signer } {
  const { privateKey } = generateKeyPairSync("ed25519");
  const pkcs8 = privateKey.export({ format: "der", type: "pkcs8" }) as Buffer;
  const seed = pkcs8.subarray(pkcs8.length - 32);
  const signer = ed25519Signer(privateKey);
  return { seed: Buffer.from(seed), publicKeyRaw: signer.publicKeyRaw() as Buffer, signer };
}
