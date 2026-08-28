import {
  McpServer,
  fromJsonSchema,
  type JsonSchemaType,
} from "@modelcontextprotocol/server";
import type { ToolPolicy } from "../policy/toolPolicy.js";
import type { ToolRegistry } from "../upstream/toolRegistry.js";

export function createGatewayServer(
  registry: ToolRegistry,
  policy: ToolPolicy,
): McpServer {
  const server = new McpServer(
    { name: "tools-gateway", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  for (const tool of registry
    .list()
    .filter(({ publicName }) => policy.allows(publicName))) {
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
        policy.enforce(tool.publicName, () =>
          registry.call(
            tool.publicName,
            isArgumentsObject(arguments_) ? arguments_ : {},
          ),
        ),
    );
  }

  return server;
}

function isArgumentsObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
