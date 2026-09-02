import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import type { ApiKeyService } from "./apiKeyService.js";
import type { CustomUpstreamService } from "./customUpstreamService.js";
import type { OAuthSessionStore } from "../auth/oauthSession.js";
import { DASHBOARD_HTML } from "../ui/dashboardHtml.js";
import { IamAiCredentialClient } from "../credential/iamAiCredentialClient.js";

const createKeySchema = z.object({
  name: z.string().trim().min(1).max(100),
  expiresAt: z.string().datetime({ offset: true }).optional(),
});

const createUpstreamSchema = z.object({
  toolPrefix: z.string().trim().min(1).max(50).regex(/^[a-z][a-z0-9_]{0,49}$/),
  endpointUrl: z.string().trim().url(),
  transport: z.enum(["streamable-http", "sse"]).default("streamable-http"),
  authType: z.enum(["bearer", "api_key", "custom_header", "none"]).default("bearer"),
  authHeaderName: z.string().trim().min(1).max(100).default("Authorization"),
  authValue: z.string().trim().optional(),
  description: z.string().trim().max(255).optional(),
});

const saveAiKeySchema = z.object({
  provider: z.enum(["OPENAI_API_KEY", "EMBEDDING_API_KEY"]),
  apiKey: z.string().trim().min(1),
  accountType: z.enum(["USER", "ORGANIZATION"]).default("USER"),
});

const checkDeviceSchema = z.object({
  deviceAuthId: z.string().trim().min(1),
  userCode: z.string().trim().min(1),
  accountType: z.enum(["USER", "ORGANIZATION"]).default("USER"),
});

export function registerManagementRoutes(
  app: FastifyInstance,
  sessions: OAuthSessionStore,
  apiKeys: ApiKeyService,
  upstreams: CustomUpstreamService,
  iamAiClient: IamAiCredentialClient = new IamAiCredentialClient(),
): void {
  app.get("/", async (_request, reply) => {
    reply.type("text/html; charset=utf-8");
    return reply.send(DASHBOARD_HTML);
  });

  app.get("/api/v1/auth/login", async (_request, reply) => {
    const { authorizationUrl } = await sessions.beginLogin();
    return reply.redirect(authorizationUrl);
  });

  app.get("/api/v1/auth/sso-callback", async (request, reply) => {
    const query = request.query as { code?: string; state?: string; error?: string };
    if (query.error || !query.code || !query.state) {
      return reply.code(400).send({ error: "Invalid SSO callback" });
    }
    try {
      const { sessionId, principal } = await sessions.completeLogin(query.code, query.state);
      await apiKeys.provisionUser(principal);
      reply.header("set-cookie", sessionCookie(sessionId));
      return reply.redirect("/");
    } catch (error) {
      request.log.error({ err: error, message: error instanceof Error ? error.message : String(error) }, "SSO callback failed");
      return reply.code(401).send({ error: "SSO authentication failed", detail: error instanceof Error ? error.message : String(error) });
    }
  });

  app.get("/api/v1/auth/me", async (request, reply) => {
    const sessionId = cookieValue(request, "tg_session");
    if (!sessionId) return reply.code(401).send({ authenticated: false });
    const principal = await sessions.resolve(sessionId);
    if (!principal) return reply.code(401).send({ authenticated: false });
    const userId = await apiKeys.provisionUser(principal);
    return {
      authenticated: true,
      user: {
        id: userId,
        email: principal.email,
        name: principal.name,
      },
    };
  });

  app.post("/api/v1/auth/logout", async (request, reply) => {
    const sessionId = cookieValue(request, "tg_session");
    if (sessionId) await sessions.revoke(sessionId);
    reply.header("set-cookie", "tg_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax");
    return reply.code(204).send();
  });

  // API Key Routes
  app.post("/api/v1/keys", async (request, reply) => {
    const userId = await authenticatedUserId(request, sessions, apiKeys);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    const parsed = createKeySchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "Invalid API key request" });
    return reply.code(201).send(await apiKeys.create(userId, parsed.data.name, parsed.data.expiresAt));
  });

  app.get("/api/v1/keys", async (request, reply) => {
    const userId = await authenticatedUserId(request, sessions, apiKeys);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    return apiKeys.list(userId);
  });

  app.delete("/api/v1/keys/:keyId", async (request, reply) => {
    const userId = await authenticatedUserId(request, sessions, apiKeys);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    const { keyId } = request.params as { keyId: string };
    if (!await apiKeys.revoke(userId, keyId)) return reply.code(404).send({ error: "API key not found" });
    return reply.code(204).send();
  });

  app.get("/api/v1/permissions", async (request, reply) => {
    const userId = await authenticatedUserId(request, sessions, apiKeys);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    return apiKeys.permissions(userId);
  });

  // Custom MCP Upstream Routes
  app.post("/api/v1/upstreams", async (request, reply) => {
    const userId = await authenticatedUserId(request, sessions, apiKeys);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    const parsed = createUpstreamSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "Invalid MCP upstream request", details: parsed.error.issues });
    }
    try {
      const created = await upstreams.create(userId, parsed.data);
      return reply.code(201).send(created);
    } catch (error) {
      return reply.code(400).send({ error: error instanceof Error ? error.message : "Failed to create upstream" });
    }
  });

  app.get("/api/v1/upstreams", async (request, reply) => {
    const userId = await authenticatedUserId(request, sessions, apiKeys);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    return upstreams.list(userId);
  });

  app.delete("/api/v1/upstreams/:id", async (request, reply) => {
    const userId = await authenticatedUserId(request, sessions, apiKeys);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    const { id } = request.params as { id: string };
    if (!await upstreams.delete(userId, id)) {
      return reply.code(404).send({ error: "Custom MCP upstream not found" });
    }
    return reply.code(204).send();
  });

  // ==========================================
  // AI 자격증명 (Codex OAuth & API Keys) Routes
  // ==========================================
  app.get("/api/v1/ai-credentials/bundle", async (request, reply) => {
    const userId = await authenticatedUserId(request, sessions, apiKeys);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    const bundle = await iamAiClient.getAiBundle(userId);
    return reply.send(bundle || {
      user_id: userId,
      codex: { linked: false },
      openai_api_key: { configured: false },
      embedding_api_key: { configured: false },
    });
  });

  app.post("/api/v1/ai-credentials/codex/device/start", async (request, reply) => {
    const userId = await authenticatedUserId(request, sessions, apiKeys);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    try {
      const init = await iamAiClient.startCodexDeviceFlow();
      return reply.send(init);
    } catch (err) {
      return reply.code(502).send({ error: "Failed to start Codex Device Flow", message: String(err) });
    }
  });

  app.post("/api/v1/ai-credentials/codex/device/check", async (request, reply) => {
    const userId = await authenticatedUserId(request, sessions, apiKeys);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    const parsed = checkDeviceSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "Invalid check request" });
    try {
      const res = await iamAiClient.checkCodexDeviceFlow(
        parsed.data.deviceAuthId,
        parsed.data.userCode,
        userId,
        undefined,
        parsed.data.accountType
      );
      return reply.send(res);
    } catch (err) {
      return reply.code(400).send({ error: "Pending or failed", message: String(err) });
    }
  });

  app.post("/api/v1/ai-credentials/keys", async (request, reply) => {
    const userId = await authenticatedUserId(request, sessions, apiKeys);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    const parsed = saveAiKeySchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "Invalid key request", details: parsed.error.issues });
    try {
      const res = await iamAiClient.saveApiKey(
        parsed.data.provider,
        parsed.data.apiKey,
        userId,
        undefined,
        parsed.data.accountType
      );
      return reply.send(res);
    } catch (err) {
      return reply.code(500).send({ error: "Failed to save AI key", message: String(err) });
    }
  });

  app.delete("/api/v1/ai-credentials/keys/:provider", async (request, reply) => {
    const userId = await authenticatedUserId(request, sessions, apiKeys);
    if (!userId) return reply.code(401).send({ error: "Unauthorized" });
    const { provider } = request.params as { provider: string };
    const validProvider = provider.toUpperCase() as "OPENAI_API_KEY" | "EMBEDDING_API_KEY" | "CODEX_OAUTH";
    const ok = await iamAiClient.deleteApiKey(validProvider, userId);
    return ok ? reply.code(204).send() : reply.code(404).send({ error: "Credential not found" });
  });
}

async function authenticatedUserId(
  request: FastifyRequest,
  sessions: OAuthSessionStore,
  apiKeys: ApiKeyService,
): Promise<string | undefined> {
  const sessionId = cookieValue(request, "tg_session");
  if (!sessionId) return undefined;
  const principal = await sessions.resolve(sessionId);
  return principal ? apiKeys.provisionUser(principal) : undefined;
}

function cookieValue(request: FastifyRequest, name: string): string | undefined {
  const cookie = request.headers.cookie;
  if (!cookie) return undefined;
  for (const part of cookie.split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return decodeURIComponent(value.join("="));
  }
  return undefined;
}

function sessionCookie(sessionId: string): string {
  return `tg_session=${encodeURIComponent(sessionId)}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}
