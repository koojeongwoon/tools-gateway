import { generateKeyPair, SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import { loadMcpOAuthConfig, McpOAuthVerifier } from "../src/auth/mcpOAuthVerifier.js";

const config = loadMcpOAuthConfig({
  AUTH_SERVER_URL: "https://auth.snappytory.com",
  TOOLS_GATEWAY_TENANT_ID: "tenant-a",
  MCP_RESOURCE_URL: "https://tools-gateway.lynply.com/mcp",
});

describe("MCP OAuth verifier", () => {
  it("maps a resource-bound IAM token to Gateway tool grants", async () => {
    const { publicKey, privateKey } = await generateKeyPair("RS256");
    const token = await new SignJWT({
      tenant_id: "tenant-a", scope: "openid mcp", email: "user@example.com", name: "User", user_version: "2",
    })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(config.issuer)
      .setAudience(config.resource)
      .setSubject("iam-user-1")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
    const query = vi.fn()
      .mockResolvedValueOnce({ rows: [{ id: "tg-user-1" }] })
      .mockResolvedValueOnce({ rows: [{
        user_id: "tg-user-1",
        system_role: "USER",
        tool_patterns: ["knowledge.*", "github.search"],
      }] });

    const principal = await new McpOAuthVerifier({ query } as never, config, async () => publicKey).verify(token);

    expect(principal).toEqual({
      userId: "tg-user-1",
      systemRole: "USER",
      toolPatterns: ["knowledge.*", "github.search"],
      scopes: ["tool:knowledge.*", "tool:github.search"],
    });
    expect(query).toHaveBeenNthCalledWith(2, expect.stringContaining("WHERE u.id = $1"), ["tg-user-1"]);
  });

  it.each([
    ["wrong audience", { audience: "another-resource", tenantId: "tenant-a", scope: "mcp" }],
    ["wrong tenant", { audience: config.resource, tenantId: "tenant-b", scope: "mcp" }],
    ["missing MCP scope", { audience: config.resource, tenantId: "tenant-a", scope: "openid" }],
  ])("rejects %s", async (_name, claims) => {
    const { publicKey, privateKey } = await generateKeyPair("RS256");
    const token = await new SignJWT({ tenant_id: claims.tenantId, scope: claims.scope, email: "user@example.com" })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(config.issuer)
      .setAudience(claims.audience)
      .setSubject("iam-user-1")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(privateKey);
    const query = vi.fn();

    await expect(new McpOAuthVerifier({ query } as never, config, async () => publicKey).verify(token))
      .resolves.toBeUndefined();
    expect(query).not.toHaveBeenCalled();
  });

  it("rejects legacy Gateway API keys without querying user grants", async () => {
    const query = vi.fn();
    const { publicKey } = await generateKeyPair("RS256");

    await expect(new McpOAuthVerifier({ query } as never, config, async () => publicKey).verify(
      "tg_live_legacy_api_key_that_is_long_enough",
    )).resolves.toBeUndefined();
    expect(query).not.toHaveBeenCalled();
  });
});
