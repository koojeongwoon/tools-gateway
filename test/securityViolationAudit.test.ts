import { describe, it, expect, vi, beforeEach } from "vitest";
import { createGatewayServer } from "../src/server/createGatewayServer.js";
import { ToolRouteMap } from "../src/domain/toolRouteMap.js";
import { ToolPolicy } from "../src/policy/toolPolicy.js";
import { AuditLogger } from "../src/audit/auditLogger.js";
import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport } from "@modelcontextprotocol/server";

describe("Security Violation Audit Logging (SIEM & Threat Audit)", () => {
  let mockPool: any;
  let auditLogger: AuditLogger;

  beforeEach(() => {
    mockPool = {
      query: vi.fn().mockResolvedValue({ rowCount: 1 }),
    };
    auditLogger = new AuditLogger(mockPool as any, { batchSize: 1 });
  });

  it("should record SECURITY_VIOLATION audit log when command injection is detected", async () => {
    const logSpy = vi.spyOn(auditLogger, "log");
    const routeMap = ToolRouteMap.empty();
    const policy = new ToolPolicy({ default: "deny", allow: ["*"], deny: [] });

    // Mock an echo tool
    const mockTool = {
      name: "echo",
      inputSchema: { type: "object" },
    };
    const mockConnection: any = {
      id: "shell",
      toolPrefix: "system",
      listTools: async () => [mockTool],
      callTool: vi.fn(),
      close: async () => undefined,
    };
    const registry = await routeMap.withConnection(mockConnection);

    const server = createGatewayServer(
      registry,
      policy,
      undefined,
      auditLogger,
      {
        requestId: "req-attack-001",
        userId: "user-attacker",
        ipAddress: "203.0.113.195",
        userAgent: "curl/8.1.2",
      },
    );

    const client = new Client({ name: "test-client", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

    await Promise.all([
      server.connect(serverTransport),
      client.connect(clientTransport),
    ]);

    // Attempt command injection
    const callResult = await client.callTool({
      name: "system.echo",
      arguments: { cmd: "hello; rm -rf /" },
    });
    expect(callResult.isError).toBe(true);

    // Verify auditLogger captured the SECURITY_VIOLATION
    expect(logSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        requestId: "req-attack-001",
        userId: "user-attacker",
        toolName: "system.echo",
        status: "SECURITY_VIOLATION",
        statusCode: 400,
        ipAddress: "203.0.113.195",
        userAgent: "curl/8.1.2",
      }),
    );

    auditLogger.stop();
    await client.close();
    await server.close();
  });
});
