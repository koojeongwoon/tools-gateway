import type { FastifyInstance, FastifyRequest } from "fastify";
import { ApiKeyScopeError, type ApiKeyService } from "./apiKeyService.js";
import type { CustomUpstreamService } from "./customUpstreamService.js";
import type { OAuthSessionStore, GatewaySession } from "../auth/oauthSession.js";
import { DASHBOARD_HTML } from "../ui/dashboardHtml.js";
import { registerAiCredentialRoutes } from "./aiCredentialRoutes.js";
import { registerGatewayResourceRoutes } from "./gatewayResourceRoutes.js";
import { IamAiCredentialClient } from "../credential/iamAiCredentialClient.js";

export function registerManagementRoutes(
  app: FastifyInstance,
  sessions: OAuthSessionStore,
  apiKeys: ApiKeyService,
  upstreams: CustomUpstreamService,
  toolCatalog: () => readonly string[],
  iamAiClient: IamAiCredentialClient = new IamAiCredentialClient(),
  iamTenantId: string,
): void {
  // 메인 접속 시 비로그인 상태면 테넌트 SSO 로그인 화면으로 즉시 리다이렉트
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
    return { signoutUrl: sessions.getSignoutUrl() };
  });

  registerGatewayResourceRoutes(app, {
    apiKeys,
    upstreams,
    toolCatalog,
    authenticatedUserId: (request) => authenticatedUserId(request, sessions, apiKeys),
  });
  registerAiCredentialRoutes(app, { sessions, iamAiClient, iamTenantId });
}

async function authenticatedUserSession(
  request: FastifyRequest,
  sessions: OAuthSessionStore,
): Promise<GatewaySession | undefined> {
  const sessionId = cookieValue(request, "tg_session");
  if (!sessionId) return undefined;
  return sessions.resolve(sessionId);
}

async function authenticatedUserId(
  request: FastifyRequest,
  sessions: OAuthSessionStore,
  apiKeys: ApiKeyService,
): Promise<string | undefined> {
  const principal = await authenticatedUserSession(request, sessions);
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
