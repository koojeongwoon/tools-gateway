import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import { registerGatewayResourceRoutes } from "../src/api/gatewayResourceRoutes.js";

describe("Gateway resource routes", () => {
  it("does not grant custom upstream tool access by default", async () => {
    const app = Fastify();
    const apiKeys = {
      permissions: vi.fn().mockResolvedValue({
        services: [],
        tools: ["github.*"],
        customToolPatterns: ["private_mcp.*"],
      }),
    };
    registerGatewayResourceRoutes(app, {
      apiKeys: apiKeys as never,
      upstreams: {} as never,
      toolCatalog: () => ["github.get_issue", "private_mcp.search"],
      authenticatedUserId: vi.fn().mockResolvedValue("user-1"),
    });

    const response = await app.inject({ method: "GET", url: "/api/v1/permissions" });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      services: [],
      tools: ["github.get_issue"],
      customToolPatterns: ["private_mcp.*"],
      toolPatterns: ["github.*", "private_mcp.*"],
    });
    await app.close();
  });

  it("requires a user session before creating Gateway API keys", async () => {
    const app = Fastify();
    const create = vi.fn();
    registerGatewayResourceRoutes(app, {
      apiKeys: { create } as never,
      upstreams: {} as never,
      toolCatalog: () => [],
      authenticatedUserId: vi.fn().mockResolvedValue(undefined),
    });

    const response = await app.inject({
      method: "POST",
      url: "/api/v1/keys",
      payload: { name: "personal-key" },
    });

    expect(response.statusCode).toBe(401);
    expect(create).not.toHaveBeenCalled();
    await app.close();
  });
});
