import { describe, it, expect } from "vitest";
import { ResilientUpstreamConnection } from "../src/upstream/resilientUpstreamConnection.js";
import type { UpstreamConnection } from "../src/upstream/upstreamConnection.js";
import type { CallToolResult } from "@modelcontextprotocol/client";

describe("Chaos Engineering & Downstream Resilience (TDD)", () => {
  it("should isolate sudden process crash / packet loss with CircuitBreaker tripping", async () => {
    let callCount = 0;
    const flakeyConnection: UpstreamConnection = {
      id: "chaos-upstream-1",
      toolPrefix: "chaos",
      async listTools() {
        return [{ name: "unstable_exec", inputSchema: { type: "object" } }];
      },
      async callTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
        callCount++;
        // Simulate MCP process death / ECONNRESET / packet drop
        throw new Error("ECONNRESET: Connection reset by downstream peer (Process Crashed)");
      },
      async close() {},
    };

    const resilient = new ResilientUpstreamConnection(flakeyConnection, {
      failureThreshold: 3,
      resetTimeoutMs: 100, // fast reset for test
    });

    // 1st to 3rd calls fail and increment failure count
    await expect(resilient.callTool("unstable_exec", {})).rejects.toThrow("ECONNRESET");
    await expect(resilient.callTool("unstable_exec", {})).rejects.toThrow("ECONNRESET");
    await expect(resilient.callTool("unstable_exec", {})).rejects.toThrow("ECONNRESET");

    // 4th call should immediately fast-fail via CircuitBreaker without hitting downstream
    const preCount = callCount;
    await expect(resilient.callTool("unstable_exec", {})).rejects.toThrow(/circuit breaker is open/i);
    expect(callCount).toBe(preCount); // Upstream was spared!

    // Wait for reset timeout (half-open)
    await new Promise((r) => setTimeout(r, 120));

    // Simulate recovery
    let recovered = false;
    flakeyConnection.callTool = async () => {
      recovered = true;
      return { content: [{ type: "text", text: "recovered successfully" }] };
    };

    const result = await resilient.callTool("unstable_exec", {});
    expect(recovered).toBe(true);
    expect(result.content[0]).toEqual({ type: "text", text: "recovered successfully" });
  });

  it("should handle partial degradation without crashing gateway process", async () => {
    let alternate = 0;
    const partialConnection: UpstreamConnection = {
      id: "chaos-upstream-2",
      toolPrefix: "partial",
      async listTools() {
        return [{ name: "degraded_tool", inputSchema: { type: "object" } }];
      },
      async callTool(): Promise<CallToolResult> {
        alternate++;
        if (alternate % 2 === 1) {
          throw new Error("504 Gateway Timeout: Upstream packet lost");
        }
        return { content: [{ type: "text", text: "success" }] };
      },
      async close() {},
    };

    const resilient = new ResilientUpstreamConnection(partialConnection, {
      failureThreshold: 5,
      resetTimeoutMs: 500,
    });

    await expect(resilient.callTool("degraded_tool", {})).rejects.toThrow("504 Gateway Timeout");
    const okRes = await resilient.callTool("degraded_tool", {});
    expect(okRes.content[0]).toEqual({ type: "text", text: "success" });
  });
});
