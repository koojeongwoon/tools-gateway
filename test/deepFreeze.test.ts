import { describe, it, expect } from "vitest";
import { deepFreeze } from "../src/utils/deepFreeze.js";

describe("deepFreeze (FP Immutability)", () => {
  it("should recursively freeze nested objects and arrays", () => {
    const original = {
      name: "tool",
      nested: {
        pattern: "*.exec",
        flags: ["read", "write"],
        meta: { level: 1 },
      },
    };

    const frozen = deepFreeze(original);

    expect(Object.isFrozen(frozen)).toBe(true);
    expect(Object.isFrozen(frozen.nested)).toBe(true);
    expect(Object.isFrozen(frozen.nested.flags)).toBe(true);
    expect(Object.isFrozen(frozen.nested.meta)).toBe(true);

    expect(() => {
      (frozen.nested as any).pattern = "changed";
    }).toThrow();

    expect(() => {
      (frozen.nested.flags as any).push("execute");
    }).toThrow();

    expect(() => {
      (frozen.nested.meta as any).level = 2;
    }).toThrow();
  });

  it("should handle null and primitives safely", () => {
    expect(deepFreeze(null)).toBe(null);
    expect(deepFreeze(123)).toBe(123);
    expect(deepFreeze("test")).toBe("test");
    expect(deepFreeze(undefined)).toBe(undefined);
  });
});
