import { AGENT_TOOL_COMMANDS, validateAgentToolsArguments, validateAgentToolsResult } from "../policy/agentToolsContract.js";
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
import { OutboundSecretLeakGuard } from "../policy/outboundSecretLeakGuard.js";
import { sanitizeToolResult } from "../policy/toolOutputSanitizer.js";
import type { JevGuardrail } from "../policy/jevGuardrail.js";
import type { JevVirtualRouter } from "../jev/jevVirtualRouter.js";

export type { GatewayRequestContext };

export interface GatewayServerOptions {
  delimiter?: string;
}

const argumentSanitizer = new ToolArgumentSanitizer({ strict: true });
const outboundSecretLeakGuard = new OutboundSecretLeakGuard();

export function createGatewayServer(
  registry: ToolRegistry | ToolRouteMap,
  policy: ToolPolicy | ToolAccessPolicy,
  scopeGuard?: ScopeGuard,
  auditLogger?: AuditLogger,
  requestContext?: GatewayRequestContext,
  jevGuardrail?: JevGuardrail,
  jevVirtualRouter?: JevVirtualRouter,
  agentToolsContracts: readonly { upstreamId: string; toolPrefix: string }[] = [],
  serverOptions?: GatewayServerOptions,
): McpServer {
  const delimiter = serverOptions?.delimiter ?? ".";

  const server = new McpServer(
    {
      name: "tools-gateway",
      version: "0.1.0",
      websiteUrl: "https://tools-gateway.lynply.com/",
    },
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

  const allowedTools: Array<(typeof tools)[number]> = [];

  for (const tool of tools) {
    const isAllowed = policy instanceof ToolAccessPolicy
      ? policy.allows(tool.publicName)
      : policy.allows(tool.publicName) && (!scopeGuard || scopeGuard.allows(tool.publicName));

    if (!isAllowed) {
      continue;
    }

    const route = registry instanceof ToolRouteMap ? registry.get(tool.publicName) : registry.getRouteMap().get(tool.publicName);
    const contract = agentToolsContracts.find(c => route?.upstreamId === c.upstreamId && tool.publicName.startsWith(c.toolPrefix + "."));
    const command = contract ? tool.publicName.slice(contract.toolPrefix.length + 1) : undefined;
    if (command && !AGENT_TOOL_COMMANDS.has(command)) throw new Error("Unsupported agent-tools data contract tool");
    // The generic smart dispatcher does not handle opaque attachments/consent data.
    if (!command) allowedTools.push(tool);

    const exposedName = delimiter === "." ? tool.publicName : tool.publicName.replaceAll(".", delimiter);

    server.registerTool(
      exposedName,
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

        const apiOperation = command === "api" && typeof argsObj.operation === "string"
          && /^(?:broker\.(?:json|forward)|documents\.(?:read|fetch|extract|validate)|cover\.generate|blob\.(?:begin|append|seal|read|release))$/.test(argsObj.operation) ? argsObj.operation : undefined;
        const auditArguments = command === "api" ? { operation: apiOperation ?? "invalid" } : command ? { argvCount: Array.isArray(argsObj.argv) ? argsObj.argv.length : 0,
          attachmentCount: argsObj.files && typeof argsObj.files === "object" ? Object.keys(argsObj.files).length : 0,
          stdinPresent: Boolean(argsObj.stdin) } : argsObj;
        return invocationContext.invoke(tool.publicName, auditArguments, async () => {
          // Security Guardrail: Validate & sanitize tool invocation arguments
          if (command) validateAgentToolsArguments(command, argsObj);
          else argumentSanitizer.validate(argsObj);

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

          if (!command) outboundSecretLeakGuard.validate(argsObj);

          if (jevGuardrail) {
            await jevGuardrail.validate(tool.publicName, command ? auditArguments : argsObj);
          }

          try {
            const rawResult = await registry.call(tool.publicName, argsObj);
            // AI Guardrail: Sanitize and redact high-entropy keys/PII from tool output
            return command ? validateAgentToolsResult(command, rawResult) : sanitizeToolResult(rawResult);
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

  // Register Jev smart meta-dispatcher if enabled and there are callable tools
  if (jevVirtualRouter && allowedTools.length > 0) {
    const metaTool = jevVirtualRouter.getVirtualToolDefinition();
    const isMetaAllowed = policy instanceof ToolAccessPolicy
      ? policy.allows(metaTool.name)
      : policy.allows(metaTool.name) && (!scopeGuard || scopeGuard.allows(metaTool.name));

    if (isMetaAllowed) {
      const exposedMetaName = delimiter === "." ? metaTool.name : metaTool.name.replaceAll(".", delimiter);
      const exposedToCanonical = new Map<string, string>();
      for (const t of allowedTools) {
        const exp = delimiter === "." ? t.publicName : t.publicName.replaceAll(".", delimiter);
        exposedToCanonical.set(exp, t.publicName);
        exposedToCanonical.set(t.publicName, t.publicName);
      }

      const candidateTools = allowedTools.map((t) => ({
        publicName: delimiter === "." ? t.publicName : t.publicName.replaceAll(".", delimiter),
        ...(t.description !== undefined ? { description: t.description } : {}),
      }));

      server.registerTool(
        exposedMetaName,
        {
          ...(metaTool.description !== undefined ? { description: metaTool.description } : {}),
          inputSchema: fromJsonSchema(metaTool.inputSchema as JsonSchemaType),
        },
        async (arguments_) => {
          const argsObj = isArgumentsObject(arguments_) ? arguments_ : {};
          const intent = String(argsObj.intent || "");
          const rawParams = isArgumentsObject(argsObj.parameters) ? argsObj.parameters : {};

          return invocationContext.invoke(metaTool.name, argsObj, async () => {
            argumentSanitizer.validate(rawParams);

            if (jevGuardrail) {
              await jevGuardrail.validate(metaTool.name, { intent, ...rawParams });
            }

            // Use Jev to decide target tool
            const decision = await jevVirtualRouter.route(intent, candidateTools);
            const targetToolName = exposedToCanonical.get(decision.selectedTool) ?? decision.selectedTool;

            // Validate target tool access policy
            if (policy instanceof ToolAccessPolicy) {
              policy.assertAllowed(targetToolName);
            } else {
              if (!policy.allows(targetToolName)) {
                throw new Error(`Target tool is not allowed by gateway policy: ${targetToolName}`);
              }
            }

            outboundSecretLeakGuard.validate(rawParams);

            try {
              const rawResult = await registry.call(targetToolName, rawParams);
              const sanitizedResult = sanitizeToolResult(rawResult);

              return {
                content: [
                  {
                    type: "text" as const,
                    text: `[Jev Dispatcher: routed to ${targetToolName} (confidence: ${(decision.confidence * 100).toFixed(1)}%)]`,
                  },
                  ...sanitizedResult.content,
                ],
                isError: sanitizedResult.isError,
              };
            } catch (upstreamError: any) {
              const sanitizedMsg = maskInternalErrorDetails(upstreamError?.message || String(upstreamError));
              const safeError = new Error(sanitizedMsg);
              (safeError as any).statusCode = upstreamError?.statusCode ?? 502;
              throw safeError;
            }
          });
        },
      );
    }
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
