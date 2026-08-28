import { describe, expect, it } from "vitest";
import { ScopeGuard } from "../src/auth/scopeGuard.js";

describe("ScopeGuard", () => {
  it("requires both service permission and API key scope", () => {
    const guard = new ScopeGuard({
      userId: "u1", apiKeyId: "k1", systemRole: "USER",
      scopes: ["knowledge:read"], permissions: { knowledge: ["read"] },
    });
    expect(guard.allows({ name: "knowledge.query", annotations: { readOnlyHint: true } })).toBe(true);
    expect(guard.allows({ name: "knowledge.delete", annotations: { readOnlyHint: false } })).toBe(false);
    expect(guard.allows({ name: "context7.query", annotations: { readOnlyHint: true } })).toBe(false);
  });

  it("treats tools without an explicit read-only annotation as write", () => {
    const guard = new ScopeGuard({
      userId: "u1", apiKeyId: "k1", systemRole: "USER",
      scopes: ["knowledge:read"], permissions: { knowledge: ["read"] },
    });
    expect(guard.allows({ name: "knowledge.unknown" })).toBe(false);
  });
});
