import type { CallToolResult, Tool } from "@modelcontextprotocol/client";
import type { UpstreamConnection } from "./upstreamConnection.js";

export type RoutedTool = Tool & {
  publicName: string;
  upstreamId: string;
  upstreamToolName: string;
};

export class ToolRegistry {
  private readonly routes = new Map<
    string,
    { connection: UpstreamConnection; tool: Tool }
  >();

  constructor(private readonly connections: UpstreamConnection[]) {}

  async refresh(): Promise<void> {
    const discovered = new Map<
      string,
      { connection: UpstreamConnection; tool: Tool }
    >();

    for (const connection of this.connections) {
      for (const tool of await connection.listTools()) {
        const publicName = `${connection.toolPrefix}.${tool.name}`;
        if (discovered.has(publicName)) {
          throw new Error(`duplicate public tool name: ${publicName}`);
        }
        discovered.set(publicName, { connection, tool });
      }
    }

    this.routes.clear();
    for (const [name, route] of discovered) {
      this.routes.set(name, route);
    }
  }

  list(): RoutedTool[] {
    return [...this.routes.entries()]
      .map(([publicName, { connection, tool }]) => ({
        ...tool,
        name: publicName,
        publicName,
        upstreamId: connection.id,
        upstreamToolName: tool.name,
      }))
      .sort((left, right) => left.publicName.localeCompare(right.publicName));
  }

  async call(
    publicName: string,
    arguments_: Record<string, unknown>,
  ): Promise<CallToolResult> {
    const route = this.routes.get(publicName);
    if (!route) {
      throw new Error(`unknown tool: ${publicName}`);
    }
    return route.connection.callTool(route.tool.name, arguments_);
  }

  clone(): ToolRegistry {
    const next = new ToolRegistry([...this.connections]);
    for (const [name, route] of this.routes) {
      next.routes.set(name, route);
    }
    return next;
  }

  async addRoute(connection: UpstreamConnection): Promise<void> {
    for (const tool of await connection.listTools()) {
      const publicName = `${connection.toolPrefix}.${tool.name}`;
      this.routes.set(publicName, { connection, tool });
    }
  }

  async close(): Promise<void> {
    await Promise.all(this.connections.map((connection) => connection.close()));
  }
}
