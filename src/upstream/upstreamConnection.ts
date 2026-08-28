import type { CallToolResult, Tool } from "@modelcontextprotocol/client";

export interface UpstreamConnection {
  readonly id: string;
  readonly toolPrefix: string;
  listTools(): Promise<Tool[]>;
  callTool(name: string, arguments_: Record<string, unknown>): Promise<CallToolResult>;
  close(): Promise<void>;
}
