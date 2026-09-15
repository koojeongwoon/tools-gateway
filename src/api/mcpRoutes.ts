import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import type { FastifyInstance } from "fastify";
import type { AuditLogger } from "../audit/auditLogger.js";
import { bearerToken } from "../auth/keyVerifier.js";
import type { McpOAuthConfig, McpOAuthVerifier } from "../auth/mcpOAuthVerifier.js";
import type { RequestToolRegistryBuilder } from "../application/requestToolRegistryBuilder.js";
import type { GatewayConfig } from "../config/upstreamConfig.js";
import { ToolAccessPolicy } from "../domain/toolAccessPolicy.js";
import { createGatewayServer } from "../server/createGatewayServer.js";

export interface McpRoutesOptions {
  config: GatewayConfig;
  oauthConfig: McpOAuthConfig;
  oauthVerifier: Pick<McpOAuthVerifier, "verify">;
  requestToolRegistryBuilder: Pick<RequestToolRegistryBuilder, "build">;
  auditLogger?: AuditLogger | undefined;
}

/** HTTP adapter for the Gateway-owned MCP protocol endpoint. */
export function registerMcpRoutes(app: FastifyInstance, options: McpRoutesOptions): void {
  app.get(new URL(options.oauthConfig.resourceMetadataUrl).pathname, async (_request, reply) =>
    reply.type("application/json").send({
      resource: options.oauthConfig.resource,
      authorization_servers: [options.oauthConfig.authorizationServer],
      scopes_supported: [options.oauthConfig.requiredScope],
      bearer_methods_supported: ["header"],
    }));

  app.post("/mcp", async (request, reply) => {
    const token = bearerToken(request.headers.authorization);
    const principal = token ? await options.oauthVerifier.verify(token) : undefined;
    if (!principal) {
      return reply
        .header(
          "WWW-Authenticate",
          `Bearer resource_metadata="${options.oauthConfig.resourceMetadataUrl}", scope="${options.oauthConfig.requiredScope}"`,
        )
        .code(401)
        .send({ error: "Unauthorized" });
    }

    const requestToolRegistry = await options.requestToolRegistryBuilder.build(principal, request.log, token);
    const accessPolicy = new ToolAccessPolicy({
      globalConfig: {
        default: "deny",
        allow: [
          ...options.config.toolPolicy.allow,
          ...requestToolRegistry.activeCustomPrefixes.map((prefix) => `${prefix}.*`),
        ],
        deny: options.config.toolPolicy.deny,
      },
      principal,
    });
    const requestContext = principal
      ? {
          requestId: request.id,
          userId: principal.userId,
          ...(principal.apiKeyId ? { apiKeyId: principal.apiKeyId } : {}),
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
