import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import type { FastifyInstance } from "fastify";
import type { AuditLogger } from "../audit/auditLogger.js";
import { bearerToken, type KeyVerifier } from "../auth/keyVerifier.js";
import type { RequestToolRegistryBuilder } from "../application/requestToolRegistryBuilder.js";
import type { GatewayConfig } from "../config/upstreamConfig.js";
import { ToolAccessPolicy } from "../domain/toolAccessPolicy.js";
import { createGatewayServer } from "../server/createGatewayServer.js";

export interface McpRoutesOptions {
  config: GatewayConfig;
  keyVerifier?: Pick<KeyVerifier, "verify"> | undefined;
  apiKeyAuthEnabled: boolean;
  requestToolRegistryBuilder: Pick<RequestToolRegistryBuilder, "build">;
  auditLogger?: AuditLogger | undefined;
}

/** HTTP adapter for the Gateway-owned MCP protocol endpoint. */
export function registerMcpRoutes(app: FastifyInstance, options: McpRoutesOptions): void {
  app.post("/mcp", async (request, reply) => {
    const token = bearerToken(request.headers.authorization);
    const principal = token && options.keyVerifier
      ? await options.keyVerifier.verify(token)
      : undefined;
    if (options.apiKeyAuthEnabled && !principal) {
      return reply.code(401).send({ error: "Unauthorized" });
    }

    const requestToolRegistry = await options.requestToolRegistryBuilder.build(principal, request.log);
    const accessPolicy = new ToolAccessPolicy({
      globalConfig: {
        default: "deny",
        allow: [
          ...options.config.toolPolicy.allow,
          ...requestToolRegistry.activeCustomPrefixes.map((prefix) => `${prefix}.*`),
        ],
        deny: options.config.toolPolicy.deny,
      },
      principal: options.apiKeyAuthEnabled ? principal : undefined,
    });
    const requestContext = principal
      ? {
          requestId: request.id,
          userId: principal.userId,
          apiKeyId: principal.apiKeyId,
          ipAddress: request.ip,
          userAgent: request.headers["user-agent"],
        }
      : undefined;

    const server = createGatewayServer(
      requestToolRegistry.registry,
      accessPolicy,
      undefined,
      options.auditLogger,
      requestContext,
    );
    const transport = new NodeStreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    await server.connect(transport);

    reply.raw.on("close", () => {
      void transport.close();
      void server.close();
      void requestToolRegistry.close();
    });

    await transport.handleRequest(request.raw, reply.raw, request.body);
  });

  for (const method of ["GET", "DELETE"] as const) {
    app.route({
      method,
      url: "/mcp",
      handler: async (_request, reply) => reply.code(405).send({ error: "Method Not Allowed" }),
    });
  }
}
