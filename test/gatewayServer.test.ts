import { Client } from "@modelcontextprotocol/client";
import {
  InMemoryTransport,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/server";
import { describe, expect, it, vi } from "vitest";
import { ToolPolicy } from "../src/policy/toolPolicy.js";
import { createGatewayServer } from "../src/server/createGatewayServer.js";
import { ToolRegistry } from "../src/upstream/toolRegistry.js";
import type { UpstreamConnection } from "../src/upstream/upstreamConnection.js";
import { ScopeGuard } from "../src/auth/scopeGuard.js";

describe("MCP gateway server", () => {
  it("exposes prefixed tools and forwards calls end to end", async () => {
    const callTool = vi.fn(async (): Promise<CallToolResult> => ({
      content: [{ type: "text", text: "forwarded" }],
    }));
    const tools: Tool[] = [
      {
        name: "get_file",
        description: "Read a repository file",
        inputSchema: {
          type: "object",
          properties: { path: { type: "string" } },
          required: ["path"],
        },
      },
      {
        name: "create_pull_request",
        inputSchema: { type: "object" },
      },
    ];
    const upstream: UpstreamConnection = {
      id: "git",
      toolPrefix: "github",
      listTools: async () => tools,
      callTool,
      close: async () => undefined,
    };
    const registry = new ToolRegistry([upstream]);
    await registry.refresh();

    const server = createGatewayServer(
      registry,
      new ToolPolicy({ default: "deny", allow: ["github.*"], deny: [] }),
      new ScopeGuard({
        userId: "user-1",
        apiKeyId: "key-1",
        systemRole: "USER",
        scopes: ["tool:github.get_file"],
        toolPatterns: ["github.get_file"],
      }),
    );
    const client = new Client({ name: "test-client", version: "1.0.0" });
    const [clientTransport, serverTransport] =
      InMemoryTransport.createLinkedPair();

    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);

    const listed = await client.listTools();
    expect(listed.tools.map(({ name }) => name)).toEqual(["github.get_file"]);

    const result = await client.callTool({
      name: "github.get_file",
      arguments: { path: "README.md" },
    });
    expect(result.content).toEqual([{ type: "text", text: "forwarded" }]);
    expect(callTool).toHaveBeenCalledWith("get_file", { path: "README.md" });

    await client.close();
    await server.close();
  });

  it("records SUCCESS audit log when tool call succeeds", async () => {
    const callTool = vi.fn(async (): Promise<CallToolResult> => ({
      content: [{ type: "text", text: "ok" }],
    }));
    const upstream: UpstreamConnection = {
      id: "git",
      toolPrefix: "github",
      listTools: async () => [{ name: "get_file", inputSchema: { type: "object" } }],
      callTool,
      close: async () => undefined,
    };
    const registry = new ToolRegistry([upstream]);
    await registry.refresh();

    const mockPool = { query: vi.fn().mockResolvedValue({ rowCount: 1 }) };
    const { AuditLogger } = await import("../src/audit/auditLogger.js");
    const auditLogger = new AuditLogger(mockPool as any);
    const logSpy = vi.spyOn(auditLogger, "log");

    const server = createGatewayServer(
      registry,
      new ToolPolicy({ default: "deny", allow: ["github.*"], deny: [] }),
      undefined,
      auditLogger,
      {
        userId: "user-123",
        apiKeyId: "key-456",
        ipAddress: "127.0.0.1",
        userAgent: "test-agent",
      },
    );

    const client = new Client({ name: "test-client", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);

    const result = await client.callTool({
      name: "github.get_file",
      arguments: {},
    });
    expect(result.content).toEqual([{ type: "text", text: "ok" }]);

    expect(logSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: "user-123",
        apiKeyId: "key-456",
        toolName: "github.get_file",
        status: "SUCCESS",
        statusCode: 200,
        ipAddress: "127.0.0.1",
        userAgent: "test-agent",
      }),
    );

    expect(mockPool.query).toHaveBeenCalledWith(
      expect.stringContaining("INSERT INTO tool_usage_logs"),
      expect.arrayContaining(["user-123", "key-456", "github.get_file", "SUCCESS", 200]),
    );

    await client.close();
    await server.close();
  });

  it("records ERROR audit log when tool call fails in upstream", async () => {
    const upstream: UpstreamConnection = {
      id: "git",
      toolPrefix: "github",
      listTools: async () => [{ name: "error_tool", inputSchema: { type: "object" } }],
      callTool: vi.fn().mockRejectedValue(new Error("upstream failure")),
      close: async () => undefined,
    };
    const registry = new ToolRegistry([upstream]);
    await registry.refresh();

    const mockPool = { query: vi.fn().mockResolvedValue({ rowCount: 1 }) };
    const { AuditLogger } = await import("../src/audit/auditLogger.js");
    const auditLogger = new AuditLogger(mockPool as any);
    const logSpy = vi.spyOn(auditLogger, "log");

    const server = createGatewayServer(
      registry,
      new ToolPolicy({ default: "deny", allow: ["github.*"], deny: [] }),
      undefined,
      auditLogger,
      {
        userId: "user-123",
        apiKeyId: "key-456",
      },
    );

    const client = new Client({ name: "test-client", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);

    const callResult = await client.callTool({
      name: "github.error_tool",
      arguments: {},
    });
    expect(callResult.isError).toBe(true);

    expect(logSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: "user-123",
        apiKeyId: "key-456",
        toolName: "github.error_tool",
        status: "ERROR",
        statusCode: 500,
      }),
    );

    await client.close();
    await server.close();
  });
});
