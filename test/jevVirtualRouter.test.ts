import { describe, expect, it, vi } from "vitest";
import { JevVirtualRouter } from "../src/jev/jevVirtualRouter.js";
import { JevClient } from "../src/jev/jevClient.js";
import { loadJevConfig } from "../src/config/jev.js";
import { ToolRegistry } from "../src/upstream/toolRegistry.js";
import { ToolPolicy } from "../src/policy/toolPolicy.js";
import { createGatewayServer } from "../src/server/createGatewayServer.js";
import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport, type CallToolResult } from "@modelcontextprotocol/server";
import type { UpstreamConnection } from "../src/upstream/upstreamConnection.js";

describe("JevVirtualRouter", () => {
  it("provides correct virtual tool definition", () => {
    const client = new JevClient(loadJevConfig({ JEV_API_KEY: "dummy" }));
    const router = new JevVirtualRouter(client);
    const def = router.getVirtualToolDefinition();

    expect(def.name).toBe("gateway.smart_dispatch");
    expect(def.inputSchema.properties).toHaveProperty("intent");
  });

  it("rejects an empty candidate list without calling Jev", async () => {
    const client = new JevClient(loadJevConfig({ JEV_API_KEY: "dummy" }));
    const decide = vi.spyOn(client, "decide");
    await expect(new JevVirtualRouter(client).route("find docs", [])).rejects.toThrow("No available tools");
    expect(decide).not.toHaveBeenCalled();
  });

  it("keeps the first-candidate fallback for an unknown choice", async () => {
    const client = new JevClient(loadJevConfig({ JEV_API_KEY: "dummy" }));
    vi.spyOn(client, "decide").mockResolvedValue({
      model: "jev-latest", answers: { selected_tool: { type: "choice", choice: "unknown" } },
    });
    const decision = await new JevVirtualRouter(client).route("find docs", [
      { publicName: "knowledge.search" }, { publicName: "github.get_file" },
    ]);
    expect(decision).toMatchObject({ selectedTool: "knowledge.search", confidence: 0 });
  });

  it("routes to single candidate without calling Jev API", async () => {
    const client = new JevClient(loadJevConfig({ JEV_API_KEY: "dummy" }));
    const decideSpy = vi.spyOn(client, "decide");
    const router = new JevVirtualRouter(client);

    const decision = await router.route("find docs", [
      { publicName: "knowledge.search", description: "Search docs" },
    ]);

    expect(decision.selectedTool).toBe("knowledge.search");
    expect(decision.confidence).toBe(1.0);
    expect(decideSpy).not.toHaveBeenCalled();
  });

  it("selects best tool using Jev choice answers when multiple candidates exist", async () => {
    const client = new JevClient(loadJevConfig({ JEV_API_KEY: "dummy" }));
    vi.spyOn(client, "decide").mockResolvedValueOnce({
      model: "jev-latest",
      answers: {
        selected_tool: {
          type: "choice",
          choice: "github.get_file",
          probabilities: { "github.get_file": 0.95, "knowledge.search": 0.05 },
        },
      },
    });

    const router = new JevVirtualRouter(client);
    const candidates = [
      { publicName: "knowledge.search", description: "Search company knowledge base" },
      { publicName: "github.get_file", description: "Fetch raw source code from GitHub repo" },
    ];

    const decision = await router.route("get repository source file", candidates);
    expect(decision.selectedTool).toBe("github.get_file");
    expect(decision.confidence).toBe(0.95);
  });

  it("falls back to first candidate gracefully on Jev API failure", async () => {
    const client = new JevClient(loadJevConfig({ JEV_API_KEY: "dummy" }));
    vi.spyOn(client, "decide").mockRejectedValueOnce(new Error("Timeout"));

    const router = new JevVirtualRouter(client);
    const candidates = [
      { publicName: "knowledge.search", description: "Search company knowledge base" },
      { publicName: "github.get_file", description: "Fetch raw source code from GitHub repo" },
    ];

    const decision = await router.route("get repository source file", candidates);
    expect(decision.selectedTool).toBe("knowledge.search");
    expect(decision.confidence).toBe(0.0);
  });

  it("safely trims oversized intent and tool descriptions to stay within token budget", async () => {
    const client = new JevClient(loadJevConfig({ JEV_API_KEY: "dummy" }));
    const decideSpy = vi.spyOn(client, "decide").mockResolvedValueOnce({
      model: "jev-latest",
      answers: {
        selected_tool: {
          type: "choice",
          choice: "tool.first",
        },
      },
    });

    const router = new JevVirtualRouter(client);
    const oversizedIntent = "query ".repeat(5000); // 30,000 chars
    const candidates = [
      { publicName: "tool.first", description: "desc ".repeat(200) }, // 1,000 chars
      { publicName: "tool.second", description: "desc ".repeat(200) },
    ];

    await router.route(oversizedIntent, candidates);
    expect(decideSpy).toHaveBeenCalledTimes(1);

    const firstCall = decideSpy.mock.calls[0];
    if (!firstCall) throw new Error("Expected Jev decide to be called");
    const passedState = firstCall[0] as { user_intent: string; candidates: any[] };
    expect(passedState.user_intent.length).toBeLessThanOrEqual(16_000);
    expect(passedState.candidates[0].description.length).toBeLessThanOrEqual(500);
  });

  it.each([
    { source: "route-map", omitDescriptions: false },
    { source: "registry", omitDescriptions: false },
    { source: "route-map", omitDescriptions: true },
    { source: "registry", omitDescriptions: true },
  ])("dispatches through $source with omitDescriptions=$omitDescriptions", async ({ source, omitDescriptions }) => {
    const callTool = vi.fn(async (tool: string, args: Record<string, unknown>): Promise<CallToolResult> => ({
      content: [{ type: "text", text: `Invoked ${tool} with ${JSON.stringify(args)}` }],
    }));

    const upstream: UpstreamConnection = {
      id: "test-upstream",
      toolPrefix: "test",
      listTools: async () => [
        { name: "read_doc", ...(omitDescriptions ? {} : { description: "Read a documentation page" }), inputSchema: { type: "object" } },
        { name: "execute_job", ...(omitDescriptions ? {} : { description: "Execute a background job" }), inputSchema: { type: "object" } },
      ],
      callTool,
      close: async () => undefined,
    };

    const registry = new ToolRegistry([upstream]);
    await registry.refresh();
    const policy = new ToolPolicy({
      default: "deny",
      allow: ["test.*", "gateway.smart_dispatch"],
      deny: [],
    });

    const client = new JevClient(loadJevConfig({ JEV_API_KEY: "dummy" }));
    vi.spyOn(client, "decide").mockResolvedValue({
      model: "jev-latest",
      answers: {
        selected_tool: {
          type: "choice",
          choice: "test.read_doc",
          probabilities: { "test.read_doc": 0.92 },
        },
        is_malicious: { type: "noul", noul: 0.01 },
      },
    });

    const router = new JevVirtualRouter(client);

    if (omitDescriptions) {
      const definition = router.getVirtualToolDefinition();
      const { description: _description, ...withoutDescription } = definition;
      vi.spyOn(router, "getVirtualToolDefinition").mockReturnValue(withoutDescription);
    }

    const server = createGatewayServer(
      source === "registry" ? registry : registry.getRouteMap(),
      policy,
      undefined,
      undefined,
      undefined,
      undefined,
      router,
    );

    const mcpClient = new Client({ name: "e2e-client", version: "1.0.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();

    await Promise.all([
      server.connect(serverTransport),
      mcpClient.connect(clientTransport),
    ]);

    const toolsList = await mcpClient.listTools();
    const toolNames = toolsList.tools.map((t) => t.name);
    expect(toolNames).toContain("test.read_doc");
    expect(toolNames).toContain("test.execute_job");
    expect(toolNames).toContain("gateway.smart_dispatch");

    // Call smart_dispatch with natural intent
    const callResult = await mcpClient.callTool({
      name: "gateway.smart_dispatch",
      arguments: {
        intent: "Please read the architecture documentation",
        parameters: { pageId: "arch-101" },
      },
    });

    expect(callTool).toHaveBeenCalledWith("read_doc", { pageId: "arch-101" });
    const textOutputs = (callResult.content as Array<{ type: string; text: string }>).map((c) => c.text);
    expect(textOutputs[0]).toContain("Jev Dispatcher: routed to test.read_doc");
    expect(textOutputs[1]).toContain("Invoked read_doc with {\"pageId\":\"arch-101\"}");

    await mcpClient.close();
    await server.close();
  });
});
