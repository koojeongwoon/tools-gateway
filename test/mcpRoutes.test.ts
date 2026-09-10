import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import { registerMcpRoutes } from "../src/api/mcpRoutes.js";

describe("MCP routes", () => {
  it("rejects an unauthenticated MCP request before building a tool registry", async () => {
    const app = Fastify();
    const build = vi.fn();
    registerMcpRoutes(app, {
      config: { upstreams: [], toolPolicy: { default: "deny", allow: [], deny: [] } },
      keyVerifier: { verify: vi.fn().mockResolvedValue(undefined) } as never,
      apiKeyAuthEnabled: true,
      requestToolRegistryBuilder: { build } as never,
    });

    const response = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: { authorization: "Bearer tg_live_invalid" },
    });

    expect(response.statusCode).toBe(401);
    expect(build).not.toHaveBeenCalled();
    await app.close();
  });

  it("rejects unsupported MCP methods", async () => {
    const app = Fastify();
    registerMcpRoutes(app, {
      config: { upstreams: [], toolPolicy: { default: "deny", allow: [], deny: [] } },
      apiKeyAuthEnabled: false,
      requestToolRegistryBuilder: { build: vi.fn() } as never,
    });

    const response = await app.inject({ method: "GET", url: "/mcp" });

    expect(response.statusCode).toBe(405);
    await app.close();
  });
});
