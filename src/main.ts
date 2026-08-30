import Fastify from "fastify";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import { loadGatewayConfig } from "./config/upstreamConfig.js";
import {
  createDatabasePool,
  loadDatabaseConfig,
} from "./config/database.js";
import { initializeDatabase } from "./database/initializeDatabase.js";
import { ToolPolicy } from "./policy/toolPolicy.js";
import { createGatewayServer } from "./server/createGatewayServer.js";
import { RemoteMcpConnection } from "./upstream/remoteMcpConnection.js";
import { ToolRegistry } from "./upstream/toolRegistry.js";
import { createClient } from "redis";
import { loadRedisConfig } from "./config/redis.js";
import { bearerToken, KeyVerifier } from "./auth/keyVerifier.js";
import { ScopeGuard } from "./auth/scopeGuard.js";
import { UserSyncConsumer } from "./events/userSyncConsumer.js";
import { loadOAuthConfig, OAuthSessionStore } from "./auth/oauthSession.js";
import { ApiKeyService } from "./api/apiKeyService.js";
import { CustomUpstreamService } from "./api/customUpstreamService.js";
import { EnvelopeCrypto } from "./crypto/envelopeCrypto.js";
import { registerManagementRoutes } from "./api/managementRoutes.js";
import { DASHBOARD_HTML } from "./ui/dashboardHtml.js";

const configPath = process.env.UPSTREAM_CONFIG ?? "config/upstreams.yaml";
const config = await loadGatewayConfig(configPath);
const databasePool = createDatabasePool(loadDatabaseConfig());
if (databasePool) {
  await initializeDatabase(databasePool);
}
const redis = databasePool ? createClient(loadRedisConfig()) : undefined;
if (redis) await redis.connect();
const keyVerifier = databasePool && redis
  ? new KeyVerifier(databasePool, redis)
  : undefined;
const eventRedis = redis?.duplicate();
if (eventRedis) await eventRedis.connect();
const userSyncConsumer = databasePool && eventRedis && keyVerifier
  ? new UserSyncConsumer(eventRedis, databasePool, keyVerifier)
  : undefined;
if (userSyncConsumer) {
  await userSyncConsumer.start();
}

const connections = [];
for (const upstream of config.upstreams.filter(({ enabled }) => enabled)) {
  connections.push(await RemoteMcpConnection.connect(upstream));
}

const registry = new ToolRegistry(connections);
await registry.refresh();
const policy = new ToolPolicy(config.toolPolicy);

const app = Fastify({ logger: true });
const apiKeyAuthEnabled = process.env.API_KEY_AUTH_ENABLED === "true";
if (apiKeyAuthEnabled && !keyVerifier) {
  throw new Error("API key authentication requires database and Redis");
}
const masterSecret = process.env.ENCRYPTION_MASTER_KEY || "tools-gateway-default-encryption-key-2026";
const envelopeCrypto = new EnvelopeCrypto(masterSecret);
const customUpstreamService = databasePool ? new CustomUpstreamService(databasePool, envelopeCrypto) : undefined;

const oauthConfig = loadOAuthConfig();
if (oauthConfig) {
  if (!databasePool || !redis || !keyVerifier || !customUpstreamService) {
    throw new Error("SSO management API requires database, Redis and customUpstreamService");
  }
  registerManagementRoutes(
    app,
    new OAuthSessionStore(redis, oauthConfig),
    new ApiKeyService(databasePool, keyVerifier),
    customUpstreamService,
  );
}

app.get("/healthz", async () => ({ status: "ok" }));
app.get("/readyz", async () => ({
  status: "ready",
  tools: registry.list().length,
}));

app.post("/mcp", async (request, reply) => {
  const token = bearerToken(request.headers.authorization);
  const principal = token && keyVerifier ? await keyVerifier.verify(token) : undefined;
  if (apiKeyAuthEnabled && !principal) {
    return reply.code(401).send({ error: "Unauthorized" });
  }
  const server = createGatewayServer(
    registry,
    policy,
    apiKeyAuthEnabled && principal ? new ScopeGuard(principal) : undefined,
  );
  const transport = new NodeStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });
  await server.connect(transport);

  reply.raw.on("close", () => {
    void transport.close();
    void server.close();
  });

  await transport.handleRequest(request.raw, reply.raw, request.body);
});

for (const method of ["GET", "DELETE"] as const) {
  app.route({
    method,
    url: "/mcp",
    handler: async (_request, reply) => {
      await reply.code(405).send({ error: "Method Not Allowed" });
    },
  });
}

const shutdown = async () => {
  await app.close();
  await registry.close();
  userSyncConsumer?.stop();
  await eventRedis?.quit();
  await redis?.quit();
  await databasePool?.end();
};

process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());

await app.listen({
  host: process.env.HOST ?? "0.0.0.0",
  port: Number(process.env.PORT ?? 3000),
});
