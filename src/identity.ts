import { getAddress } from "ethers";
import { HEDERA_CHAIN_ID, type HederaNetwork } from "./domain.js";

// Namespaces H-Seal verifies. "hedera" covers both bare 0.0.x ids and the
// hedera:<net>:0.0.x CAIP-10 form; the on-chain key type (Ed25519 vs ECDSA)
// decides the signing scheme, not the identity string.
export type Namespace = "hedera" | "eip155" | "xrpl" | "solana" | "stellar";

export interface ParsedIdentity {
  namespace: Namespace;
  chain: string; // CAIP-2, e.g. "eip155:8453" or "hedera:mainnet"
  address: string;
  // The EIP-712 domain chainId to sign under. eip155 uses its own chain ref;
  // Hedera-ECDSA recovers under the Hedera chainId (295/296).
  evmChainId: number;
}

// Resolve a caller/provider identity to the values the signer needs. Mirrors the
// dispatch in H-Seal tip712.ts: CAIP-10 first, bare Hedera account as a fallback.
export function parseIdentity(identity: string, network: HederaNetwork): ParsedIdentity {
  const parts = identity.split(":");
  if (parts.length >= 3) {
    const ns = parts[0] as string;
    const ref = parts[1] as string;
    const address = parts.slice(2).join(":");
    const chain = `${ns}:${ref}`;
    if (ns === "eip155") {
      let addr = address;
      try {
        addr = getAddress(address);
      } catch {
        // leave as provided; the server validates the format
      }
      return { namespace: "eip155", chain, address: addr, evmChainId: Number(ref) };
    }
    if (ns === "hedera") {
      return { namespace: "hedera", chain, address, evmChainId: HEDERA_CHAIN_ID[network] };
    }
    if (ns === "xrpl") {
      return { namespace: "xrpl", chain, address, evmChainId: HEDERA_CHAIN_ID[network] };
    }
    if (ns === "solana") {
      return { namespace: "solana", chain, address, evmChainId: HEDERA_CHAIN_ID[network] };
    }
    if (ns === "stellar") {
      // address is the Stellar G... account (StrKey ed25519 public key); the
      // server validates the format and decodes it.
      return { namespace: "stellar", chain, address, evmChainId: HEDERA_CHAIN_ID[network] };
    }
    throw new Error(`unsupported identity namespace: ${ns}`);
  }

  if (/^\d+\.\d+\.\d+$/.test(identity)) {
    const chain = network === "testnet" ? "hedera:testnet" : "hedera:mainnet";
    return { namespace: "hedera", chain, address: identity, evmChainId: HEDERA_CHAIN_ID[network] };
  }

  throw new Error(`invalid identity format: ${identity}`);
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
