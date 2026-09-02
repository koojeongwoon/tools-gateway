import { describe, expect, it, vi } from "vitest";
import type { Tool } from "@modelcontextprotocol/client";
import { ToolRouteMap } from "../src/domain/toolRouteMap.js";
import type { UpstreamConnection } from "../src/upstream/upstreamConnection.js";

describe("ToolRouteMap (Domain Aggregate)", () => {
  const dummyTool: Tool = {
    name: "read_file",
    description: "read file tool",
    inputSchema: { type: "object" },
  };

  const mockUpstream: UpstreamConnection = {
    id: "fs-upstream",
    toolPrefix: "fs",
    listTools: async () => [dummyTool],
    callTool: vi.fn().mockResolvedValue({ content: [{ type: "text", text: "file-content" }] }),
    close: vi.fn().mockResolvedValue(undefined),
  };

  it("builds route map from connections and lists routes immutably", async () => {
    const routeMap = await ToolRouteMap.fromConnections([mockUpstream]);
    const routes = routeMap.list();

    expect(routes).toHaveLength(1);
    expect(routes[0]?.publicName).toBe("fs.read_file");
    expect(routes[0]?.upstreamId).toBe("fs-upstream");
    expect(routes[0]?.upstreamToolName).toBe("read_file");
  });

  it("throws error if duplicate public tool name exists across upstreams", async () => {
    const duplicateUpstream: UpstreamConnection = {
      id: "fs-duplicate",
      toolPrefix: "fs",
      listTools: async () => [dummyTool],
      callTool: vi.fn(),
      close: vi.fn(),
    };

    await expect(
      ToolRouteMap.fromConnections([mockUpstream, duplicateUpstream]),
    ).rejects.toThrow("duplicate public tool name: fs.read_file");
  });

  it("calls routed tool through corresponding connection", async () => {
    const routeMap = await ToolRouteMap.fromConnections([mockUpstream]);
    const result = await routeMap.call("fs.read_file", { path: "test.txt" });

    expect(result).toEqual({ content: [{ type: "text", text: "file-content" }] });
    expect(mockUpstream.callTool).toHaveBeenCalledWith("read_file", { path: "test.txt" });
  });

  it("throws error when calling unknown tool", async () => {
    const routeMap = await ToolRouteMap.fromConnections([mockUpstream]);
    await expect(routeMap.call("unknown.tool", {})).rejects.toThrow("unknown tool: unknown.tool");
  });

  it("returns a new immutable ToolRouteMap when adding a connection", async () => {
    const baseMap = await ToolRouteMap.fromConnections([mockUpstream]);

    const newUpstream: UpstreamConnection = {
      id: "git-upstream",
      toolPrefix: "git",
      listTools: async () => [{ name: "commit", inputSchema: { type: "object" } }],
      callTool: vi.fn(),
      close: vi.fn(),
    };

    const extendedMap = await baseMap.withConnection(newUpstream);

    // baseMap remains unchanged
    expect(baseMap.list()).toHaveLength(1);
    expect(extendedMap.list()).toHaveLength(2);
    expect(extendedMap.has("git.commit")).toBe(true);
  });
});
