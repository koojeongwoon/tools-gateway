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
});
