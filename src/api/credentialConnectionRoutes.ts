import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import type { OAuthSessionStore } from "../auth/oauthSession.js";
import {
  CredentialBrokerClient,
  CredentialBrokerError,
} from "../credential/credentialBrokerClient.js";

const OwnerType = z.enum(["USER", "TENANT"]);
const RegisterRequest = z.object({
  owner_type: OwnerType,
  provider: z.string().min(1).max(64),
  allowed_actions: z.array(z.string().min(1)).min(1),
  granted_scopes: z.array(z.string().min(1)).default([]),
  secret: z.string().min(1),
  expires_at: z.string().datetime({ offset: true }).nullable().optional(),
});
const RotateRequest = z.object({
  owner_type: OwnerType,
  secret: z.string().min(1),
  expires_at: z.string().datetime({ offset: true }).nullable().optional(),
});
const OwnerQuery = z.object({ owner_type: OwnerType });
const ConnectionParams = z.object({ connectionId: z.string().uuid() });

export function registerCredentialConnectionRoutes(
  app: FastifyInstance,
  sessions: Pick<OAuthSessionStore, "resolve">,
  broker: CredentialBrokerClient,
): void {
  app.post("/api/v1/credential-connections", async (request, reply) => {
    const session = await userSession(request, sessions);
    if (!session) return reply.code(401).send({ error: "Unauthorized" });
    if (!session.iamAccessToken) return relogin(reply);
    const body = RegisterRequest.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ error: "Invalid connection request" });
    try {
      return reply.code(201).send(await broker.register(session.iamAccessToken, body.data));
    } catch (error) {
      return brokerFailure(reply, error);
    }
  });

  app.get("/api/v1/credential-connections", async (request, reply) => {
    const session = await userSession(request, sessions);
    if (!session) return reply.code(401).send({ error: "Unauthorized" });
    if (!session.iamAccessToken) return relogin(reply);
    const query = OwnerQuery.safeParse(request.query);
    if (!query.success) return reply.code(400).send({ error: "Invalid owner type" });
    try {
      return reply.send(await broker.list(session.iamAccessToken, query.data.owner_type));
    } catch (error) {
      return brokerFailure(reply, error);
    }
  });

  app.get("/api/v1/credential-connections/:connectionId", async (request, reply) => {
    const session = await userSession(request, sessions);
    if (!session) return reply.code(401).send({ error: "Unauthorized" });
    if (!session.iamAccessToken) return relogin(reply);
    const params = ConnectionParams.safeParse(request.params);
    const query = OwnerQuery.safeParse(request.query);
    if (!params.success || !query.success) return reply.code(400).send({ error: "Invalid connection request" });
    try {
      return reply.send(await broker.status(
        session.iamAccessToken,
        params.data.connectionId,
        query.data.owner_type,
      ));
    } catch (error) {
      return brokerFailure(reply, error);
    }
  });

  app.post("/api/v1/credential-connections/:connectionId/rotate", async (request, reply) => {
    const session = await userSession(request, sessions);
    if (!session) return reply.code(401).send({ error: "Unauthorized" });
    if (!session.iamAccessToken) return relogin(reply);
    const params = ConnectionParams.safeParse(request.params);
    const body = RotateRequest.safeParse(request.body);
    if (!params.success || !body.success) return reply.code(400).send({ error: "Invalid rotation request" });
    try {
      return reply.send(await broker.rotate(session.iamAccessToken, params.data.connectionId, body.data));
    } catch (error) {
      return brokerFailure(reply, error);
    }
  });

  app.post("/api/v1/credential-connections/:connectionId/revoke", async (request, reply) => {
    const session = await userSession(request, sessions);
    if (!session) return reply.code(401).send({ error: "Unauthorized" });
    if (!session.iamAccessToken) return relogin(reply);
    const params = ConnectionParams.safeParse(request.params);
    const query = OwnerQuery.safeParse(request.query);
    if (!params.success || !query.success) return reply.code(400).send({ error: "Invalid revoke request" });
    try {
      return reply.send(await broker.revoke(
        session.iamAccessToken,
        params.data.connectionId,
        query.data.owner_type,
      ));
    } catch (error) {
      return brokerFailure(reply, error);
    }
  });
}

async function userSession(
  request: FastifyRequest,
  sessions: Pick<OAuthSessionStore, "resolve">,
) {
  const sessionId = cookieValue(request, "tg_session");
  return sessionId ? sessions.resolve(sessionId) : undefined;
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

function relogin(reply: { code(status: number): { send(body: unknown): unknown } }) {
  return reply.code(401).send({ error: "IAM access token expired; please sign in again" });
}

function brokerFailure(
  reply: { code(status: number): { send(body: unknown): unknown } },
  error: unknown,
) {
  if (error instanceof CredentialBrokerError) {
    const status = error.status >= 400 && error.status < 600 ? error.status : 502;
    return reply.code(status).send({ error: "Credential Broker request failed", code: error.code });
  }
  return reply.code(502).send({ error: "Credential Broker request failed" });
}
