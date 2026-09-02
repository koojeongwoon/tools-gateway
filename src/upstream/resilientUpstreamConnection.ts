import type { CallToolResult, Tool } from "@modelcontextprotocol/client";
import { CircuitBreaker, type CircuitBreakerOptions } from "../resilience/circuitBreaker.js";
import type { UpstreamConnection } from "./upstreamConnection.js";

export class ResilientUpstreamConnection implements UpstreamConnection {
  readonly id: string;
  readonly toolPrefix: string;
  readonly breaker: CircuitBreaker;

  constructor(
    private readonly inner: UpstreamConnection,
    breakerOptions?: CircuitBreakerOptions,
  ) {
    this.id = inner.id;
    this.toolPrefix = inner.toolPrefix;
    this.breaker = new CircuitBreaker(inner.id, breakerOptions);
  }

  async listTools(): Promise<Tool[]> {
    return this.breaker.execute(() => this.inner.listTools());
  }

  async callTool(
    name: string,
    arguments_: Record<string, unknown>,
  ): Promise<CallToolResult> {
    return this.breaker.execute(() => this.inner.callTool(name, arguments_));
  }

  async close(): Promise<void> {
    return this.inner.close();
  }
}
