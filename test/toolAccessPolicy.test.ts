import { describe, expect, it } from "vitest";
import { ToolAccessPolicy } from "../src/domain/toolAccessPolicy.js";

describe("ToolAccessPolicy (Domain Policy)", () => {
  it("evaluates global allow/deny rules correctly", () => {
    const policy = new ToolAccessPolicy({
      globalConfig: {
        default: "deny",
        allow: ["github.*", "slack.send_message"],
        deny: ["github.delete_*"],
      },
    });

    expect(policy.allows("github.get_file")).toBe(true);
    expect(policy.allows("slack.send_message")).toBe(true);
    expect(policy.allows("github.delete_repo")).toBe(false);
    expect(policy.allows("other.tool")).toBe(false);
  });

  it("evaluates principal scopes and tool patterns when principal is present", () => {
    const policy = new ToolAccessPolicy({
      globalConfig: {
        default: "deny",
        allow: ["github.*", "slack.*"],
        deny: [],
      },
      principal: {
        userId: "user-1",
        apiKeyId: "key-1",
        systemRole: "USER",
        scopes: ["tool:github.get_file"],
        toolPatterns: ["github.*"],
      },
    });

    expect(policy.allows("github.get_file")).toBe(true);
    // Not allowed by principal scopes
    expect(policy.allows("github.create_pr")).toBe(false);
    expect(policy.allows("slack.send_message")).toBe(false);
  });

  it("throws forbidden error on assertAllowed when unauthorized", () => {
    const policy = new ToolAccessPolicy({
      globalConfig: { default: "deny", allow: ["github.get_file"], deny: [] },
    });

    expect(() => policy.assertAllowed("github.get_file")).not.toThrow();
    expect(() => policy.assertAllowed("github.delete_repo")).toThrow(/not allowed/);
  });

  it("creates a new policy with additional allowed patterns", () => {
    const basePolicy = new ToolAccessPolicy({
      globalConfig: { default: "deny", allow: ["github.get_file"], deny: [] },
    });

    const extendedPolicy = basePolicy.withAllowedPattern("custom.*");
    expect(basePolicy.allows("custom.my_tool")).toBe(false);
    expect(extendedPolicy.allows("custom.my_tool")).toBe(true);
  });
});
