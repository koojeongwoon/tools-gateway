import type { CallToolResult, Tool } from "@modelcontextprotocol/client";
import { describe, expect, it, vi } from "vitest";
import { ToolRegistry } from "../src/upstream/toolRegistry.js";
import type { UpstreamConnection } from "../src/upstream/upstreamConnection.js";

function fakeConnection(
  id: string,
  toolPrefix: string,
  tools: Tool[],
): UpstreamConnection & { callTool: ReturnType<typeof vi.fn> } {
  return {
    id,
    toolPrefix,
    listTools: async () => tools,
    callTool: vi.fn(async (): Promise<CallToolResult> => ({
      content: [{ type: "text", text: "ok" }],
    })),
    close: async () => undefined,
  };
}

describe("ToolRegistry", () => {
  it("prefixes and sorts tools discovered from upstream MCP servers", async () => {
    const registry = new ToolRegistry([
      fakeConnection("k8s", "kubernetes", [
        { name: "get_pods", inputSchema: { type: "object" } },
      ]),
      fakeConnection("git", "github", [
        { name: "get_file", inputSchema: { type: "object" } },
      ]),
    ]);

    await registry.refresh();

    expect(registry.list().map(({ publicName }) => publicName)).toEqual([
      "github.get_file",
      "kubernetes.get_pods",
    ]);
  });

  it("routes a public tool call to the original upstream tool name", async () => {
    const github = fakeConnection("git", "github", [
      { name: "get_file", inputSchema: { type: "object" } },
    ]);
    const registry = new ToolRegistry([github]);
    await registry.refresh();

    await registry.call("github.get_file", { path: "README.md" });

    expect(github.callTool).toHaveBeenCalledWith("get_file", {
      path: "README.md",
    });
  });

  it("fails closed for unknown public tool names", async () => {
    const registry = new ToolRegistry([]);
    await registry.refresh();

    await expect(registry.call("unknown.delete", {})).rejects.toThrow(
      "unknown tool",
    );
  });
});
