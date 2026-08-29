import { describe, expect, it } from "vitest";
import { ScopeGuard } from "../src/auth/scopeGuard.js";

describe("ScopeGuard", () => {
  it("requires both user and API key permission for the exact tool", () => {
    const guard = new ScopeGuard({
      userId: "u1", apiKeyId: "k1", systemRole: "USER",
      scopes: ["tool:knowledge.query"], toolPatterns: ["knowledge.query"],
    });
    expect(guard.allows("knowledge.query")).toBe(true);
    expect(guard.allows("knowledge.delete")).toBe(false);
    expect(guard.allows("context7.query")).toBe(false);
  });

  it("supports operator-approved namespace patterns without annotations", () => {
    const guard = new ScopeGuard({
      userId: "u1", apiKeyId: "k1", systemRole: "USER",
      scopes: ["tool:knowledge.*"], toolPatterns: ["knowledge.*"],
    });
    expect(guard.allows("knowledge.query")).toBe(true);
    expect(guard.allows("knowledge.index")).toBe(true);
    expect(guard.allows("knowledgeAdmin.delete")).toBe(false);
  });
});
