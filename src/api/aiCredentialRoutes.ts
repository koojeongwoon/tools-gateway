import type { FastifyInstance, FastifyRequest } from "fastify";
import type { GatewaySession, OAuthSessionStore } from "../auth/oauthSession.js";
import { IamAiCredentialClient } from "../credential/iamAiCredentialClient.js";
import { CheckDeviceRequestDto, SaveAiKeyRequestDto } from "./dtos/managementDtos.js";

export interface AiCredentialRoutesOptions {
  sessions: Pick<OAuthSessionStore, "resolve">;
  iamAiClient: IamAiCredentialClient;
  iamTenantId: string;
}

/**
 * HTTP adapter for IAM-owned AI credentials. Gateway only holds the opaque
 * session token long enough to forward user-linking calls and exposes a
 * status-only service bundle to its dashboard.
 */
export function registerAiCredentialRoutes(
  app: FastifyInstance,
  { sessions, iamAiClient, iamTenantId }: AiCredentialRoutesOptions,
): void {
  app.get("/api/v1/ai-credentials/bundle", async (request, reply) => {
    const session = await authenticatedUserSession(request, sessions);
    if (!session) return reply.code(401).send({ error: "Unauthorized" });
    const status = await iamAiClient.getCredentialStatus(iamTenantId);
    return reply.send(status || {
      codex: { linked: false },
      openai_api_key: { configured: false },
      embedding_api_key: { configured: false },
    });
  });

  app.post("/api/v1/ai-credentials/codex/device/start", async (request, reply) => {
    const session = await authenticatedUserSession(request, sessions);
    if (!session) return reply.code(401).send({ error: "Unauthorized" });
    if (!session.iamAccessToken) {
      return reply.code(401).send({ error: "IAM access token expired; please sign in again" });
    }
    try {
      return reply.send(await iamAiClient.startCodexDeviceFlow(session.iamAccessToken));
    } catch (err) {
      return reply.code(502).send({ error: "Failed to start Codex Device Flow", message: String(err) });
    }
  });

  app.post("/api/v1/ai-credentials/codex/device/check", async (request, reply) => {
    const session = await authenticatedUserSession(request, sessions);
    if (!session) return reply.code(401).send({ error: "Unauthorized" });
    if (!session.iamAccessToken) {
      return reply.code(401).send({ error: "IAM access token expired; please sign in again" });
    }
    const parsed = CheckDeviceRequestDto.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "Invalid check request" });
    try {
      return reply.send(await iamAiClient.checkCodexDeviceFlow(
        session.iamAccessToken,
        parsed.data.deviceAuthId,
        parsed.data.userCode,
      ));
    } catch (err) {
      return reply.code(400).send({ error: "Pending or failed", message: String(err) });
    }
  });

  app.post("/api/v1/ai-credentials/keys", async (request, reply) => {
    const session = await authenticatedUserSession(request, sessions);
    if (!session) return reply.code(401).send({ error: "Unauthorized" });
    if (!session.iamAccessToken) {
      return reply.code(401).send({ error: "IAM access token expired; please sign in again" });
    }
    const parsed = SaveAiKeyRequestDto.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ error: "Invalid key request", details: parsed.error.issues });
    try {
      return reply.send(await iamAiClient.saveApiKey(
        session.iamAccessToken,
        parsed.data.provider,
        parsed.data.apiKey,
      ));
    } catch (err) {
      return reply.code(500).send({ error: "Failed to save AI key", message: String(err) });
    }
  });

  app.delete("/api/v1/ai-credentials/keys/:provider", async (request, reply) => {
    const session = await authenticatedUserSession(request, sessions);
    if (!session) return reply.code(401).send({ error: "Unauthorized" });
    if (!session.iamAccessToken) {
      return reply.code(401).send({ error: "IAM access token expired; please sign in again" });
    }
    const { provider } = request.params as { provider: string };
    const validProvider = provider.toUpperCase() as "OPENAI_API_KEY" | "EMBEDDING_API_KEY" | "CODEX_OAUTH";
    const ok = await iamAiClient.deleteApiKey(session.iamAccessToken, validProvider);
    return ok ? reply.code(204).send() : reply.code(404).send({ error: "Credential not found" });
  });
}

async function authenticatedUserSession(
  request: FastifyRequest,
  sessions: Pick<OAuthSessionStore, "resolve">,
): Promise<GatewaySession | undefined> {
  const sessionId = cookieValue(request, "tg_session");
  if (!sessionId) return undefined;
  return sessions.resolve(sessionId);
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
