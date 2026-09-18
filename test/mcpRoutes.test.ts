import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import { registerMcpRoutes } from "../src/api/mcpRoutes.js";

const oauthConfig = {
  resource: "https://tools-gateway.lynply.com/mcp",
  resourceMetadataUrl: "https://tools-gateway.lynply.com/.well-known/oauth-protected-resource/mcp",
  authorizationServer: "https://auth.snappytory.com/t/tenant-a",
  issuer: "https://auth.snappytory.com/t/tenant-a",
  jwksUri: "https://auth.snappytory.com/t/tenant-a/oauth2/jwks",
  tenantId: "tenant-a",
  clientId: "tools-gateway-service",
  requiredScope: "mcp",
  serviceAccessEnforcementEnabled: false,
};

describe("MCP routes", () => {
  it("rejects an unauthenticated MCP request before building a tool registry", async () => {
    const app = Fastify();
    const build = vi.fn();
    registerMcpRoutes(app, {
      config: { upstreams: [], toolPolicy: { default: "deny", allow: [], deny: [] } },
      oauthConfig,
      oauthVerifier: { verify: vi.fn().mockResolvedValue(undefined) },
      requestToolRegistryBuilder: { build } as never,
    });

    const response = await app.inject({
      method: "POST",
      url: "/mcp",
      headers: { authorization: "Bearer tg_live_invalid" },
    });

    expect(response.statusCode).toBe(401);
    expect(response.headers["www-authenticate"]).toBe(
      'Bearer resource_metadata="https://tools-gateway.lynply.com/.well-known/oauth-protected-resource/mcp", scope="mcp"',
    );
    expect(build).not.toHaveBeenCalled();
    await app.close();
  });

  it("rejects unsupported MCP methods", async () => {
    const app = Fastify();
    registerMcpRoutes(app, {
      config: { upstreams: [], toolPolicy: { default: "deny", allow: [], deny: [] } },
      oauthConfig,
      oauthVerifier: { verify: vi.fn() },
      requestToolRegistryBuilder: { build: vi.fn() } as never,
    });

    const response = await app.inject({ method: "GET", url: "/mcp" });

    expect(response.statusCode).toBe(405);
    await app.close();
  });

  it("publishes OAuth protected resource metadata", async () => {
    const app = Fastify();
    registerMcpRoutes(app, {
      config: { upstreams: [], toolPolicy: { default: "deny", allow: [], deny: [] } },
      oauthConfig,
      oauthVerifier: { verify: vi.fn() },
      requestToolRegistryBuilder: { build: vi.fn() } as never,
    });

    const response = await app.inject({
      method: "GET",
      url: "/.well-known/oauth-protected-resource/mcp",
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      resource: oauthConfig.resource,
      authorization_servers: [oauthConfig.authorizationServer],
      scopes_supported: ["mcp"],
      bearer_methods_supported: ["header"],
    });
    await app.close();
  });
});
