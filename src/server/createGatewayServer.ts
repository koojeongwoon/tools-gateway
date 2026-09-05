import {
  McpServer,
  fromJsonSchema,
  type JsonSchemaType,
} from "@modelcontextprotocol/server";
import type { ToolPolicy } from "../policy/toolPolicy.js";
import type { ToolRegistry } from "../upstream/toolRegistry.js";
import type { ScopeGuard } from "../auth/scopeGuard.js";
import type { AuditLogger } from "../audit/auditLogger.js";
import { ToolRouteMap } from "../domain/toolRouteMap.js";
import { ToolAccessPolicy } from "../domain/toolAccessPolicy.js";
import {
  ToolInvocationContext,
  type GatewayRequestContext,
} from "../domain/toolInvocationContext.js";
import { ToolArgumentSanitizer } from "../policy/toolArgumentSanitizer.js";
import { sanitizeToolResult } from "../policy/toolOutputSanitizer.js";

export type { GatewayRequestContext };

const argumentSanitizer = new ToolArgumentSanitizer({ strict: true });

export function createGatewayServer(
  registry: ToolRegistry | ToolRouteMap,
  policy: ToolPolicy | ToolAccessPolicy,
  scopeGuard?: ScopeGuard,
  auditLogger?: AuditLogger,
  requestContext?: GatewayRequestContext,
): McpServer {
  const server = new McpServer(
    { name: "tools-gateway", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  const invocationContext = new ToolInvocationContext({
    requestContext,
    auditLogger,
  });

  // Normalize route map and list
  const tools = registry instanceof ToolRouteMap
    ? registry.list().map((r) => ({
        publicName: r.publicName,
        title: r.schema.title,
        description: r.schema.description,
        inputSchema: r.schema.inputSchema,
        outputSchema: r.schema.outputSchema,
        annotations: r.schema.annotations,
      }))
    : registry.list();

  for (const tool of tools) {
    const isAllowed = policy instanceof ToolAccessPolicy
      ? policy.allows(tool.publicName)
      : policy.allows(tool.publicName) && (!scopeGuard || scopeGuard.allows(tool.publicName));

    if (!isAllowed) {
      continue;
    }

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
        const argsObj = isArgumentsObject(arguments_) ? arguments_ : {};

        // Security Guardrail: Validate & sanitize tool invocation arguments
        argumentSanitizer.validate(argsObj);

        return invocationContext.invoke(tool.publicName, argsObj, async () => {
          if (policy instanceof ToolAccessPolicy) {
            policy.assertAllowed(tool.publicName);
          } else {
            if (!policy.allows(tool.publicName)) {
              throw new Error(`tool is not allowed by gateway policy: ${tool.publicName}`);
            }
            if (scopeGuard && !scopeGuard.allows(tool.publicName)) {
              const err = new Error(`tool is outside API key scope: ${tool.publicName}`);
              (err as any).statusCode = 403;
              throw err;
            }
          }

          try {
            const rawResult = await registry.call(tool.publicName, argsObj);
            // AI Guardrail: Sanitize and redact high-entropy keys/PII from tool output
            return sanitizeToolResult(rawResult);
          } catch (upstreamError: any) {
            // Data Protection: Mask sensitive downstream host/IP/internal stack details
            const sanitizedMsg = maskInternalErrorDetails(upstreamError?.message || String(upstreamError));
            const safeError = new Error(sanitizedMsg);
            (safeError as any).statusCode = upstreamError?.statusCode ?? 502;
            throw safeError;
          }
        });
      },
    );
  }

  return server;
}

function maskInternalErrorDetails(message: string): string {
  // Strip internal IP addresses (e.g., 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.0.0.1)
  let cleaned = message.replace(/\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1)\b/g, "[internal-ip]");
  // Strip node internal stack paths / filesystem details
  cleaned = cleaned.replace(/\/(?:Users|home|root|app|var)\/[a-zA-Z0-9_/.-]+/g, "[internal-path]");
  return cleaned;
}

function isArgumentsObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
