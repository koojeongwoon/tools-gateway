import type { CallToolResult, Tool } from "@modelcontextprotocol/client";
import type { UpstreamConnection } from "../upstream/upstreamConnection.js";
import { deepFreeze } from "../utils/deepFreeze.js";

export interface ToolRoute {
  readonly publicName: string;
  readonly upstreamId: string;
  readonly upstreamToolName: string;
  readonly schema: Tool;
  readonly connection: UpstreamConnection;
}

export class ToolRouteMap {
  private readonly routes: ReadonlyMap<string, ToolRoute>;

  private constructor(routes: Map<string, ToolRoute> | ReadonlyMap<string, ToolRoute>) {
    this.routes = new Map(routes);
  }

  static empty(): ToolRouteMap {
    return new ToolRouteMap(new Map());
  }

  static async fromConnections(
    connections: readonly UpstreamConnection[],
  ): Promise<ToolRouteMap> {
    const routeMap = new Map<string, ToolRoute>();

    for (const connection of connections) {
      if (!connection.toolPrefix || !/^[a-z0-9_-]+$/i.test(connection.toolPrefix)) {
        throw new Error(`Invalid upstream toolPrefix invariant: ${connection.toolPrefix}`);
      }
      const tools = await connection.listTools();
      for (const tool of tools) {
        const publicName = `${connection.toolPrefix}.${tool.name}`;
        if (routeMap.has(publicName)) {
          throw new Error(`duplicate public tool name: ${publicName}`);
        }
        routeMap.set(publicName, {
          publicName,
          upstreamId: connection.id,
          upstreamToolName: tool.name,
          schema: deepFreeze(tool),
          connection,
        });
      }
    }

    return new ToolRouteMap(routeMap);
  }

  list(): readonly ToolRoute[] {
    return deepFreeze(
      [...this.routes.values()].sort((a, b) => a.publicName.localeCompare(b.publicName)),
    );
  }

  get(publicName: string): ToolRoute | undefined {
    return this.routes.get(publicName);
  }

  has(publicName: string): boolean {
    return this.routes.has(publicName);
  }

  async call(
    publicName: string,
    arguments_: Record<string, unknown>,
  ): Promise<CallToolResult> {
    const route = this.get(publicName);
    if (!route) {
      throw new Error(`unknown tool: ${publicName}`);
    }
    return route.connection.callTool(route.upstreamToolName, arguments_);
  }

  async withConnection(connection: UpstreamConnection): Promise<ToolRouteMap> {
    const newRoutes = new Map(this.routes);
    const tools = await connection.listTools();

    for (const tool of tools) {
      const publicName = `${connection.toolPrefix}.${tool.name}`;
      newRoutes.set(publicName, {
        publicName,
        upstreamId: connection.id,
        upstreamToolName: tool.name,
        schema: tool,
        connection,
      });
    }

    return new ToolRouteMap(newRoutes);
  }

  async close(): Promise<void> {
    const closed = new Set<string>();
    for (const route of this.routes.values()) {
      if (!closed.has(route.upstreamId)) {
        closed.add(route.upstreamId);
        await route.connection.close();
      }
    }
  }
}
