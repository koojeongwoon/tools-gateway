import type { FastifyInstance, FastifyRequest } from "fastify";
import { matchesToolPattern } from "../auth/scopeGuard.js";
import { ApiKeyScopeError, type ApiKeyService } from "./apiKeyService.js";
import type { CustomUpstreamService } from "./customUpstreamService.js";
import { CreateKeyRequestDto, CreateUpstreamRequestDto } from "./dtos/managementDtos.js";

export interface GatewayResourceRoutesOptions {
  apiKeys: ApiKeyService;
  upstreams: CustomUpstreamService;
  toolCatalog: () => readonly string[];
  authenticatedUserId: (request: FastifyRequest) => Promise<string | undefined>;
}

/** Gateway-owned resources: API keys, explicit tool scopes, and custom MCP upstreams. */
export function registerGatewayResourceRoutes(
  app: FastifyInstance,
  { apiKeys, upstreams, toolCatalog, authenticatedUserId }: GatewayResourceRoutesOptions,
): void {
  app.post("/api/v1/keys", async (request, reply) => {
    const userId = await authenticatedUserId(request);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    const parsed = CreateKeyRequestDto.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "Invalid API key request" });
    try {
      return reply.code(201).send(await apiKeys.create(
        userId,
        parsed.data.name,
        parsed.data.expiresAt,
        parsed.data.toolPatterns,
      ));
    } catch (error) {
      if (error instanceof ApiKeyScopeError) {
        return reply.code(403).send({ error: "Requested tool scope is not permitted" });
      }
      throw error;
    }
  });

  app.get("/api/v1/keys", async (request, reply) => {
    const userId = await authenticatedUserId(request);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    return apiKeys.list(userId);
  });

  app.delete("/api/v1/keys/:keyId", async (request, reply) => {
    const userId = await authenticatedUserId(request);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    const { keyId } = request.params as { keyId: string };
    if (!await apiKeys.revoke(userId, keyId)) return reply.code(404).send({ error: "API key not found" });
    return reply.code(204).send();
  });

  app.get("/api/v1/permissions", async (request, reply) => {
    const userId = await authenticatedUserId(request);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    const permissions = await apiKeys.permissions(userId) as {
      services: unknown[];
      tools: string[];
      customToolPatterns?: string[];
    };
    const toolPatterns = [...permissions.tools, ...(permissions.customToolPatterns ?? [])];
    return {
      ...permissions,
      toolPatterns,
      tools: toolCatalog().filter((toolName) =>
        permissions.tools.some((pattern) => matchesToolPattern(pattern, toolName)),
      ),
    };
  });

  app.post("/api/v1/upstreams", async (request, reply) => {
    const userId = await authenticatedUserId(request);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    const parsed = CreateUpstreamRequestDto.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "Invalid MCP upstream request", details: parsed.error.issues });
    }
    try {
      return reply.code(201).send(await upstreams.create(userId, parsed.data));
    } catch (error) {
      return reply.code(400).send({ error: error instanceof Error ? error.message : "Failed to create upstream" });
    }
  });

  app.get("/api/v1/upstreams", async (request, reply) => {
    const userId = await authenticatedUserId(request);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    return upstreams.list(userId);
  });

  app.delete("/api/v1/upstreams/:id", async (request, reply) => {
    const userId = await authenticatedUserId(request);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    const { id } = request.params as { id: string };
    if (!await upstreams.delete(userId, id)) {
      return reply.code(404).send({ error: "Custom MCP upstream not found" });
    }
    return reply.code(204).send();
  });
}
