import { describe, it, expect } from "vitest";
import { ToolAccessPolicy } from "../src/domain/toolAccessPolicy.js";
import { ToolRouteMap } from "../src/domain/toolRouteMap.js";
import type { UpstreamConnection } from "../src/upstream/upstreamConnection.js";

describe("Domain Invariant Validations (DDD)", () => {
  it("should throw invariant violation for invalid/empty tool policy patterns", () => {
    expect(() => {
      new ToolAccessPolicy({
        globalConfig: {
          default: "deny",
          allow: [""], // empty string invalid
          deny: [],
        },
      });
    }).toThrow(/must be a non-empty string/i);

    expect(() => {
      new ToolAccessPolicy({
        globalConfig: {
          default: "deny",
          allow: ["valid.*"],
          deny: ["invalid\nnewline.*"],
        },
      });
    }).toThrow(/invalid characters in tool policy pattern/i);
  });

  it("should enforce domain invariants on upstream connection toolPrefix in ToolRouteMap", async () => {
    const invalidConnection: UpstreamConnection = {
      id: "bad-upstream",
      toolPrefix: "invalid prefix with spaces!",
      async listTools() {
        return [{ name: "someTool", inputSchema: { type: "object" } }];
      },
      async callTool() {
        return { content: [] };
      },
      async close() {},
    };

    await expect(
      ToolRouteMap.fromConnections([invalidConnection]),
    ).rejects.toThrow(/Invalid upstream toolPrefix invariant/i);
  });
});
