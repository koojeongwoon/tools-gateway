import {
  McpServer,
  fromJsonSchema,
  type JsonSchemaType,
} from "@modelcontextprotocol/server";
import type { ToolPolicy } from "../policy/toolPolicy.js";
import type { ToolRegistry } from "../upstream/toolRegistry.js";
import type { ScopeGuard } from "../auth/scopeGuard.js";

export function createGatewayServer(
  registry: ToolRegistry,
  policy: ToolPolicy,
  scopeGuard?: ScopeGuard,
): McpServer {
  const server = new McpServer(
    { name: "tools-gateway", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  for (const tool of registry
    .list()
    .filter(
      ({ publicName, annotations }) =>
        policy.allows(publicName) &&
        (!scopeGuard || scopeGuard.allows({ name: publicName, annotations })),
    )) {
    server.registerTool(
      tool.publicName,
      {
        ...(tool.title ? { title: tool.title } : {}),
        ...(tool.description ? { description: tool.description } : {}),
        inputSchema: fromJsonSchema(tool.inputSchema as JsonSchemaType),
        ...(tool.outputSchema
          ? {
              outputSchema: fromJsonSchema(
                tool.outputSchema as JsonSchemaType,
              ),
            }
          : {}),
        ...(tool.annotations ? { annotations: tool.annotations } : {}),
      },
      async (arguments_) =>
        policy.enforce(tool.publicName, async () => {
          if (scopeGuard && !scopeGuard.allows({
            name: tool.publicName,
            annotations: tool.annotations,
          })) {
            throw new Error(`tool is outside API key scope: ${tool.publicName}`);
          }
          return registry.call(
            tool.publicName,
            isArgumentsObject(arguments_) ? arguments_ : {},
          );
        }),
    );
  }

  return server;
}

function isArgumentsObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
