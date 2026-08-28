import { describe, expect, it } from "vitest";
import {
  parseGatewayConfig,
  resolveUpstreamHeaders,
} from "../src/config/upstreamConfig.js";

describe("upstream config", () => {
  it("applies safe defaults without accepting secrets", () => {
    const config = parseGatewayConfig({
      upstreams: [
        {
          id: "github",
          toolPrefix: "github",
          networkScope: "cluster",
          endpoint: "http://github-mcp.tools.svc.cluster.local/mcp",
          transport: "streamable-http",
        },
      ],
      toolPolicy: { default: "deny", allow: ["github.*"] },
    });

    expect(config.upstreams[0]).toMatchObject({
      enabled: true,
      timeoutMs: 30_000,
    });
  });

  it("rejects duplicate tool prefixes", () => {
    expect(() =>
      parseGatewayConfig({
        upstreams: [
          {
            id: "one",
            toolPrefix: "shared",
            networkScope: "external",
            endpoint: "https://one.example/mcp",
            transport: "streamable-http",
          },
          {
            id: "two",
            toolPrefix: "shared",
            networkScope: "external",
            endpoint: "https://two.example/mcp",
            transport: "streamable-http",
          },
        ],
        toolPolicy: { default: "deny", allow: ["shared.*"] },
      }),
    ).toThrow("duplicate upstream toolPrefix");
  });

  it("resolves upstream headers from environment variable references", () => {
    const config = parseGatewayConfig({
      upstreams: [
        {
          id: "knowledge",
          toolPrefix: "knowledge",
          networkScope: "cluster",
          endpoint: "http://mcp-server.llm-wiki.svc.cluster.local/mcp",
          transport: "streamable-http",
          headers: {
            Authorization: { env: "KNOWLEDGE_AUTHORIZATION" },
          },
        },
      ],
      toolPolicy: { default: "deny", allow: ["knowledge.*"] },
    });

    expect(
      resolveUpstreamHeaders(config.upstreams[0]!, {
        KNOWLEDGE_AUTHORIZATION: "Bearer test-value",
      }),
    ).toEqual({ Authorization: "Bearer test-value" });
  });

  it("fails closed when a referenced header environment variable is missing", () => {
    const config = parseGatewayConfig({
      upstreams: [
        {
          id: "context7",
          toolPrefix: "context7",
          networkScope: "external",
          endpoint: "https://mcp.context7.com/mcp",
          transport: "streamable-http",
          headers: {
            Authorization: { env: "CONTEXT7_AUTHORIZATION" },
          },
        },
      ],
      toolPolicy: { default: "deny", allow: ["context7.*"] },
    });

    expect(() => resolveUpstreamHeaders(config.upstreams[0]!, {})).toThrow(
      "CONTEXT7_AUTHORIZATION",
    );
  });

  it("rejects an external URL declared as a cluster upstream", () => {
    expect(() =>
      parseGatewayConfig({
        upstreams: [
          {
            id: "context7",
            toolPrefix: "context7",
            networkScope: "cluster",
            endpoint: "https://mcp.context7.com/mcp",
            transport: "streamable-http",
          },
        ],
        toolPolicy: { default: "deny", allow: ["context7.*"] },
      }),
    ).toThrow("Kubernetes Service hostname");
  });

  it("requires https for an external upstream", () => {
    expect(() =>
      parseGatewayConfig({
        upstreams: [
          {
            id: "vendor",
            toolPrefix: "vendor",
            networkScope: "external",
            endpoint: "http://mcp.vendor.example/mcp",
            transport: "streamable-http",
          },
        ],
        toolPolicy: { default: "deny", allow: ["vendor.*"] },
      }),
    ).toThrow("must use https");
  });

  it.each([
    "https://localhost/mcp",
    "https://127.0.0.1/mcp",
    "https://10.0.0.4/mcp",
    "https://[::1]/mcp",
    "https://[fd00::1]/mcp",
    "https://service.namespace.svc.cluster.local/mcp",
  ])("rejects forbidden external target %s", (endpoint) => {
    expect(() =>
      parseGatewayConfig({
        upstreams: [
          {
            id: "blocked",
            toolPrefix: "blocked",
            networkScope: "external",
            endpoint,
            transport: "streamable-http",
          },
        ],
        toolPolicy: { default: "deny", allow: ["blocked.*"] },
      }),
    ).toThrow("must not target");
  });
});
