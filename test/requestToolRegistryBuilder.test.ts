import { describe, expect, it, vi } from "vitest";
import type { CustomMcpUpstream } from "../src/api/customUpstreamService.js";
import { RequestToolRegistryBuilder, type RequestLogger } from "../src/application/requestToolRegistryBuilder.js";
import { ToolRegistry } from "../src/upstream/toolRegistry.js";
import type { UpstreamConnection } from "../src/upstream/upstreamConnection.js";

const principal = {
  userId: "user-1",
  apiKeyId: "key-1",
  systemRole: "USER",
  scopes: ["tool:github.*"],
  toolPatterns: ["github.*"],
};

const logger: RequestLogger = { warn: vi.fn(), error: vi.fn() };

function customUpstream(overrides: Partial<CustomMcpUpstream> = {}): CustomMcpUpstream {
  return {
    id: "custom-1",
    userId: "user-1",
    toolPrefix: "github",
    endpointUrl: "https://mcp.example.com/mcp",
    transport: "streamable-http",
    authType: "bearer",
    authHeaderName: "Authorization",
    isEnabled: true,
    createdAt: "2026-09-10T00:00:00Z",
    updatedAt: "2026-09-10T00:00:00Z",
    ...overrides,
  };
}

function emptyRegistry(): ToolRegistry {
  return new ToolRegistry([]);
}

describe("RequestToolRegistryBuilder", () => {
  it("adds only the owner's streamable custom tools and normalizes bearer auth", async () => {
    const source = {
      list: vi.fn().mockResolvedValue([customUpstream(), customUpstream({ isEnabled: false, toolPrefix: "disabled" })]),
      getDecryptedAuthValue: vi.fn().mockResolvedValue({
        authType: "bearer",
        authHeaderName: "Authorization",
        authValue: "secret-token",
      }),
    };
    const connection: UpstreamConnection = {
      id: "custom-1",
      toolPrefix: "github",
      listTools: vi.fn().mockResolvedValue([{ name: "get_issue", inputSchema: { type: "object" } }]),
      callTool: vi.fn(),
      close: vi.fn(),
    };
    const factory = vi.fn().mockResolvedValue(connection);
    const builder = new RequestToolRegistryBuilder(emptyRegistry(), source, factory, async () => undefined);

    const result = await builder.build(principal, logger);

    expect(result.registry.list().map((tool) => tool.publicName)).toEqual(["github.get_issue"]);
    expect(result.activeCustomPrefixes).toEqual(["github"]);
    expect(factory).toHaveBeenCalledWith(expect.objectContaining({ endpoint: "https://mcp.example.com/mcp" }), {
      Authorization: "Bearer secret-token",
    });
    await result.close();
    expect(connection.close).toHaveBeenCalledOnce();
  });

  it("does not publish a prefix when connection or route registration fails", async () => {
    const source = {
      list: vi.fn().mockResolvedValue([customUpstream()]),
      getDecryptedAuthValue: vi.fn().mockResolvedValue(undefined),
    };
    const connection: UpstreamConnection = {
      id: "custom-1",
      toolPrefix: "github",
      listTools: vi.fn().mockRejectedValue(new Error("upstream unavailable")),
      callTool: vi.fn(),
      close: vi.fn(),
    };
    const builder = new RequestToolRegistryBuilder(
      emptyRegistry(),
      source,
      vi.fn().mockResolvedValue(connection),
      async () => undefined,
    );

    const result = await builder.build(principal, logger);

    expect(result.activeCustomPrefixes).toEqual([]);
    expect(connection.close).toHaveBeenCalledOnce();
    expect(logger.error).toHaveBeenCalledOnce();
  });

  it("revalidates the endpoint before reading credentials or connecting", async () => {
    const source = {
      list: vi.fn().mockResolvedValue([customUpstream()]),
      getDecryptedAuthValue: vi.fn(),
    };
    const factory = vi.fn();
    const endpointValidator = vi.fn().mockRejectedValue(new Error("DNS now resolves privately"));
    const builder = new RequestToolRegistryBuilder(emptyRegistry(), source, factory, endpointValidator);

    const result = await builder.build(principal, logger);

    expect(result.activeCustomPrefixes).toEqual([]);
    expect(endpointValidator).toHaveBeenCalledWith("https://mcp.example.com/mcp");
    expect(source.getDecryptedAuthValue).not.toHaveBeenCalled();
    expect(factory).not.toHaveBeenCalled();
  });
});
