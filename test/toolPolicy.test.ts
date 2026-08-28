import { describe, expect, it, vi } from "vitest";
import { ToolPolicy } from "../src/policy/toolPolicy.js";

describe("ToolPolicy", () => {
  it("allows matching tools and denies everything else", () => {
    const policy = new ToolPolicy({
      default: "deny",
      allow: ["github.get_*"],
      deny: [],
    });

    expect(policy.allows("github.get_file")).toBe(true);
    expect(policy.allows("github.create_pull_request")).toBe(false);
    expect(policy.allows("kubernetes.get_pods")).toBe(false);
  });

  it("gives deny rules precedence over allow rules", () => {
    const policy = new ToolPolicy({
      default: "deny",
      allow: ["kubernetes.*"],
      deny: ["kubernetes.delete_*"],
    });

    expect(policy.allows("kubernetes.get_pods")).toBe(true);
    expect(policy.allows("kubernetes.delete_pod")).toBe(false);
  });

  it("does not execute a denied operation", async () => {
    const operation = vi.fn(async () => "called");
    const policy = new ToolPolicy({
      default: "deny",
      allow: [],
      deny: [],
    });

    await expect(policy.enforce("github.get_file", operation)).rejects.toThrow(
      "not allowed",
    );
    expect(operation).not.toHaveBeenCalled();
  });
});
