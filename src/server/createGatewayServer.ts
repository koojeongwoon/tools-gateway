import {
  McpServer,
  fromJsonSchema,
  type JsonSchemaType,
} from "@modelcontextprotocol/server";
import type { ToolPolicy } from "../policy/toolPolicy.js";
import type { ToolRegistry } from "../upstream/toolRegistry.js";
import type { ScopeGuard } from "../auth/scopeGuard.js";
import type { AuditLogger } from "../audit/auditLogger.js";

export interface GatewayRequestContext {
  userId?: string | undefined;
  apiKeyId?: string | undefined;
  ipAddress?: string | undefined;
  userAgent?: string | undefined;
}

export function createGatewayServer(
  registry: ToolRegistry,
  policy: ToolPolicy,
  scopeGuard?: ScopeGuard,
  auditLogger?: AuditLogger,
  requestContext?: GatewayRequestContext,
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
        (!scopeGuard || scopeGuard.allows(publicName)),
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
      async (arguments_) => {
        const start = performance.now();
        const userId = requestContext?.userId ?? "anonymous";
        const apiKeyId = requestContext?.apiKeyId;
        const ipAddress = requestContext?.ipAddress;
        const userAgent = requestContext?.userAgent;

        try {
          const result = await policy.enforce(tool.publicName, async () => {
            if (scopeGuard && !scopeGuard.allows(tool.publicName)) {
              const err = new Error(`tool is outside API key scope: ${tool.publicName}`);
              (err as any).statusCode = 403;
              throw err;
            }
            return registry.call(
              tool.publicName,
              isArgumentsObject(arguments_) ? arguments_ : {},
            );
          });

          if (auditLogger && requestContext?.userId) {
            const durationMs = performance.now() - start;
            const isError = (result as any)?.isError === true;
            void auditLogger.log({
              userId,
              apiKeyId,
              toolName: tool.publicName,
              status: isError ? "ERROR" : "SUCCESS",
              statusCode: isError ? 500 : 200,
              durationMs,
              ipAddress,
              userAgent,
            });
          }

          return result;
        } catch (error) {
          if (auditLogger && requestContext?.userId) {
            const durationMs = performance.now() - start;
            const isForbidden =
              (error as any)?.statusCode === 403 ||
              (error instanceof Error && error.message.includes("outside API key scope"));
            void auditLogger.log({
              userId,
              apiKeyId,
              toolName: tool.publicName,
              status: isForbidden ? "FORBIDDEN" : "ERROR",
              statusCode: isForbidden ? 403 : 500,
              durationMs,
              ipAddress,
              userAgent,
            });
          }
          throw error;
        }
      },
    );
  }

  return server;
}

function isArgumentsObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
