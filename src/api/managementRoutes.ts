import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import type { ApiKeyService } from "./apiKeyService.js";
import type { OAuthSessionStore } from "../auth/oauthSession.js";
import { DASHBOARD_HTML } from "../ui/dashboardHtml.js";

const createKeySchema = z.object({
  name: z.string().trim().min(1).max(100),
  expiresAt: z.string().datetime({ offset: true }).optional(),
});

export function registerManagementRoutes(
  app: FastifyInstance,
  sessions: OAuthSessionStore,
  apiKeys: ApiKeyService,
): void {
  // 메인 접속 시 비로그인 상태면 자동으로 SSO 로그인 화면으로 리다이렉트
  app.get("/", async (request, reply) => {
    const sessionId = cookieValue(request, "tg_session");
    if (!sessionId) {
      const { authorizationUrl } = await sessions.beginLogin();
      return reply.redirect(authorizationUrl);
    }
    const principal = await sessions.resolve(sessionId);
    if (!principal) {
      const { authorizationUrl } = await sessions.beginLogin();
      return reply.redirect(authorizationUrl);
    }
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
      // 로그인 완료 후 대시보드 메인 화면으로 리다이렉트
      return reply.redirect("/");
    } catch (error) {
      request.log.warn({ errorType: error instanceof Error ? error.name : "UnknownError" }, "SSO callback failed");
      return reply.code(401).send({ error: "SSO authentication failed" });
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
