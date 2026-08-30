import {
  Client,
  StreamableHTTPClientTransport,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/client";
import {
  resolveUpstreamHeaders,
  type UpstreamConfig,
} from "../config/upstreamConfig.js";
import type { UpstreamConnection } from "./upstreamConnection.js";

export class RemoteMcpConnection implements UpstreamConnection {
  readonly id: string;
  readonly toolPrefix: string;

  private readonly client: Client;
  private readonly transport: StreamableHTTPClientTransport;
  private readonly timeoutMs: number;

  private constructor(config: UpstreamConfig, customHeaders?: Record<string, string>) {
    this.id = config.id;
    this.toolPrefix = config.toolPrefix;
    this.timeoutMs = config.timeoutMs;
    this.client = new Client({ name: "tools-gateway", version: "0.1.0" });
    const headers = { ...resolveUpstreamHeaders(config), ...customHeaders };
    this.transport = new StreamableHTTPClientTransport(new URL(config.endpoint), {
      ...(Object.keys(headers).length > 0
        ? { requestInit: { headers } }
        : {}),
    });
  }

  static async connect(
    config: UpstreamConfig,
    customHeaders?: Record<string, string>,
  ): Promise<RemoteMcpConnection> {
    const connection = new RemoteMcpConnection(config, customHeaders);
    await connection.client.connect(connection.transport);
    return connection;
  }

  async listTools(): Promise<Tool[]> {
    const result = await this.client.listTools();
    return result.tools;
  }

  callTool(
    name: string,
    arguments_: Record<string, unknown>,
  ): Promise<CallToolResult> {
    return this.client.callTool(
      { name, arguments: arguments_ },
      { timeout: this.timeoutMs },
    );
  }

  async close(): Promise<void> {
    await this.transport.terminateSession();
    await this.client.close();
  }
}
