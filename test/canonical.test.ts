import { describe, it, expect } from "vitest";
import { canonicalJson, sha256Hex } from "../src/index.js";

describe("canonicalJson", () => {
  it("sorts object keys deterministically regardless of insertion order", () => {
    const a = canonicalJson({ b: 1, a: 2, c: { z: 1, y: 2 } });
    const b = canonicalJson({ c: { y: 2, z: 1 }, a: 2, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":2,"b":1,"c":{"y":2,"z":1}}');
  });

  it("preserves array order", () => {
    expect(canonicalJson([3, 1, 2])).toBe("[3,1,2]");
  });
});

describe("sha256Hex", () => {
  it("is stable across key order for objects and prefixed with the scheme", () => {
    const h1 = sha256Hex({ method: "POST", path: "/x" });
    const h2 = sha256Hex({ path: "/x", method: "POST" });
    expect(h1).toBe(h2);
    expect(h1.startsWith("sha256:")).toBe(true);
    expect(h1).toHaveLength("sha256:".length + 64);
  });

  it("hashes raw strings as bytes", () => {
    expect(sha256Hex("hello")).toBe(
      "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    );
  });
});
