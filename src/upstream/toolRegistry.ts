import type { CallToolResult, Tool } from "@modelcontextprotocol/client";
import { ToolRouteMap, type ToolRoute } from "../domain/toolRouteMap.js";
import type { UpstreamConnection } from "./upstreamConnection.js";

export type RoutedTool = Tool & {
  publicName: string;
  upstreamId: string;
  upstreamToolName: string;
};

export class ToolRegistry {
  private routeMap: ToolRouteMap = ToolRouteMap.empty();

  constructor(private readonly connections: readonly UpstreamConnection[]) {}

  async refresh(): Promise<void> {
    this.routeMap = await ToolRouteMap.fromConnections(this.connections);
  }

  getRouteMap(): ToolRouteMap {
    return this.routeMap;
  }

  list(): RoutedTool[] {
    return this.routeMap.list().map((route) => ({
      ...route.schema,
      name: route.publicName,
      publicName: route.publicName,
      upstreamId: route.upstreamId,
      upstreamToolName: route.upstreamToolName,
    }));
  }

  async call(
    publicName: string,
    arguments_: Record<string, unknown>,
  ): Promise<CallToolResult> {
    return this.routeMap.call(publicName, arguments_);
  }

  clone(): ToolRegistry {
    const next = new ToolRegistry([...this.connections]);
    next.routeMap = this.routeMap;
    return next;
  }

  async addRoute(connection: UpstreamConnection): Promise<void> {
    this.routeMap = await this.routeMap.withConnection(connection);
  }

  async close(): Promise<void> {
    await this.routeMap.close();
  }
}
