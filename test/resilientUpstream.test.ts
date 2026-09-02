import { describe, expect, it, vi } from "vitest";
import { ResilientUpstreamConnection } from "../src/upstream/resilientUpstreamConnection.js";
import { CircuitBreakerOpenError } from "../src/resilience/circuitBreaker.js";
import type { UpstreamConnection } from "../src/upstream/upstreamConnection.js";
import { ToolRouteMap } from "../src/domain/toolRouteMap.js";

describe("Resilient Upstream Connection (TDD Circuit Breaker & Resilience)", () => {
  it("protects upstream from cascading failures by tripping circuit breaker on repeated errors", async () => {
    const failingCallTool = vi.fn().mockRejectedValue(new Error("ETIMEDOUT: Connection timed out"));
    const rawUpstream: UpstreamConnection = {
      id: "slow-service",
      toolPrefix: "slow",
      listTools: async () => [{ name: "query", inputSchema: { type: "object" } }],
      callTool: failingCallTool,
      close: async () => undefined,
    };

    const resilientUpstream = new ResilientUpstreamConnection(rawUpstream, {
      failureThreshold: 2,
      resetTimeoutMs: 50,
    });

    const routeMap = await ToolRouteMap.fromConnections([resilientUpstream]);

    // 1st failure: upstream is called
    await expect(routeMap.call("slow.query", {})).rejects.toThrow("ETIMEDOUT");
    expect(failingCallTool).toHaveBeenCalledTimes(1);

    // 2nd failure: upstream is called, trips the breaker to OPEN
    await expect(routeMap.call("slow.query", {})).rejects.toThrow("ETIMEDOUT");
    expect(failingCallTool).toHaveBeenCalledTimes(2);

    // 3rd call: Circuit is OPEN, fails fast with CircuitBreakerOpenError without invoking upstream
    await expect(routeMap.call("slow.query", {})).rejects.toBeInstanceOf(CircuitBreakerOpenError);
    expect(failingCallTool).toHaveBeenCalledTimes(2); // didn't increase!
  });

  it("recovers and closes circuit when downstream MCP server comes back online", async () => {
    let shouldFail = true;
    const callTool = vi.fn().mockImplementation(async () => {
      if (shouldFail) {
        throw new Error("500 Internal Server Error");
      }
      return { content: [{ type: "text", text: "recovered data" }] };
    });

    const rawUpstream: UpstreamConnection = {
      id: "recovering-service",
      toolPrefix: "service",
      listTools: async () => [{ name: "fetch", inputSchema: { type: "object" } }],
      callTool,
      close: async () => undefined,
    };

    const resilientUpstream = new ResilientUpstreamConnection(rawUpstream, {
      failureThreshold: 2,
      resetTimeoutMs: 60,
    });

    const routeMap = await ToolRouteMap.fromConnections([resilientUpstream]);

    // Cause 2 failures to open circuit
    await expect(routeMap.call("service.fetch", {})).rejects.toThrow("500");
    await expect(routeMap.call("service.fetch", {})).rejects.toThrow("500");

    // Fast-fails while OPEN
    await expect(routeMap.call("service.fetch", {})).rejects.toBeInstanceOf(CircuitBreakerOpenError);

    // Downstream service recovers
    shouldFail = false;

    // Wait for resetTimeoutMs
    await new Promise((resolve) => setTimeout(resolve, 80));

    // Next call succeeds in HALF_OPEN and closes circuit
    const result = await routeMap.call("service.fetch", {});
    expect(result).toEqual({ content: [{ type: "text", text: "recovered data" }] });

    // Subsequent calls succeed normally in CLOSED state
    const nextResult = await routeMap.call("service.fetch", {});
    expect(nextResult).toEqual({ content: [{ type: "text", text: "recovered data" }] });
  });
});
