import Fastify from "fastify";
import { loadGatewayConfig } from "./config/upstreamConfig.js";
import {
  createDatabasePool,
  loadDatabaseConfig,
} from "./config/database.js";
import { initializeDatabase } from "./database/initializeDatabase.js";
import { RemoteMcpConnection } from "./upstream/remoteMcpConnection.js";
import { ResilientUpstreamConnection } from "./upstream/resilientUpstreamConnection.js";
import { ToolRegistry } from "./upstream/toolRegistry.js";
import { RequestToolRegistryBuilder } from "./application/requestToolRegistryBuilder.js";
import { createClient } from "redis";
import { loadRedisConfig } from "./config/redis.js";
import { KeyVerifier } from "./auth/keyVerifier.js";
import { UserSyncConsumer } from "./events/userSyncConsumer.js";
import { UserLifecycleConsumer } from "./events/userLifecycleConsumer.js";
import { loadOAuthConfig, OAuthSessionStore } from "./auth/oauthSession.js";
import { ApiKeyService } from "./api/apiKeyService.js";
import { CustomUpstreamService } from "./api/customUpstreamService.js";
import { EnvelopeCrypto } from "./crypto/envelopeCrypto.js";
import { AuditLogger } from "./audit/auditLogger.js";
import { registerManagementRoutes } from "./api/managementRoutes.js";
import { registerSecurityPlugins } from "./server/registerSecurityPlugins.js";
import { loadR2AuditConfig } from "./config/r2.js";
import { R2AuditArchiver } from "./audit/r2AuditArchiver.js";
import { registerMcpRoutes } from "./api/mcpRoutes.js";
import { loadMcpOAuthConfig, McpOAuthVerifier } from "./auth/mcpOAuthVerifier.js";
import { IamDelegationClient } from "./auth/iamDelegationClient.js";

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
const lifecycleRedis = redis?.duplicate();
if (lifecycleRedis) await lifecycleRedis.connect();
const lifecycleConfig = loadMcpOAuthConfig();
const userLifecycleConsumer = databasePool && lifecycleRedis && keyVerifier
  ? new UserLifecycleConsumer(lifecycleRedis, databasePool, keyVerifier, {
      issuer: lifecycleConfig.issuer,
      tenantId: lifecycleConfig.tenantId,
    })
  : undefined;
if (userLifecycleConsumer) await userLifecycleConsumer.start();

const connections = [];
for (const upstream of config.upstreams.filter(({ enabled, auth }) =>
  enabled && auth.mode === "provider-credential")) {
  const rawConnection = await RemoteMcpConnection.connect(upstream);
  const resilientConnection = new ResilientUpstreamConnection(rawConnection, {
    failureThreshold: 5,
    resetTimeoutMs: 30000,
  });
  connections.push(resilientConnection);
}

const registry = new ToolRegistry(connections);
await registry.refresh();

const app = Fastify({
  logger: {
    level: process.env.LOG_LEVEL || "info",
  },
});

// Production Security Plugins (Helmet, CORS, Rate-Limiting)
await registerSecurityPlugins(app, {
  rateLimitMax: Number(process.env.RATE_LIMIT_MAX ?? 1000),
  rateLimitTimeWindow: process.env.RATE_LIMIT_WINDOW ?? "1 minute",
});

const isProduction = process.env.NODE_ENV === "production";
const defaultKey = "tools-gateway-default-encryption-key-2026";
if (isProduction && (!process.env.ENCRYPTION_MASTER_KEY || process.env.ENCRYPTION_MASTER_KEY === defaultKey)) {
  throw new Error("CRITICAL SECURITY VIOLATION: ENCRYPTION_MASTER_KEY must be securely configured in production!");
}
const masterSecret = process.env.ENCRYPTION_MASTER_KEY || defaultKey;
const envelopeCrypto = new EnvelopeCrypto(masterSecret);
const customUpstreamService = databasePool ? new CustomUpstreamService(databasePool, envelopeCrypto) : undefined;
const delegatedUpstreams = config.upstreams.filter(({ enabled, auth }) =>
  enabled && auth.mode === "gateway-delegation");
const delegationClient = delegatedUpstreams.length > 0
  ? new IamDelegationClient(
      process.env.AUTH_SERVER_URL ?? "https://auth.snappytory.com",
      process.env.TOOLS_GATEWAY_CLIENT_ID ?? "",
      process.env.TOOLS_GATEWAY_CLIENT_SECRET ?? "",
    )
  : undefined;
if (delegatedUpstreams.length > 0
    && (!process.env.TOOLS_GATEWAY_CLIENT_ID || !process.env.TOOLS_GATEWAY_CLIENT_SECRET)) {
  throw new Error("Gateway delegation requires Tools Gateway client credentials");
}
const requestToolRegistryBuilder = new RequestToolRegistryBuilder(
  registry,
  customUpstreamService,
  undefined,
  undefined,
  delegatedUpstreams,
  delegationClient,
);
const auditLogger = databasePool ? new AuditLogger(databasePool) : undefined;
const r2AuditConfig = loadR2AuditConfig();
const r2AuditArchiver = databasePool && r2AuditConfig.enabled
  ? new R2AuditArchiver(r2AuditConfig, databasePool)
  : undefined;
if (r2AuditArchiver) {
  r2AuditArchiver.start();
}

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
    () => registry.list().map((tool) => tool.publicName),
  );
}

app.get("/healthz", async () => ({ status: "ok" }));
app.get("/readyz", async () => ({
  status: "ready",
  tools: registry.list().length,
}));

const mcpOAuthConfig = loadMcpOAuthConfig();
if (!databasePool) {
  throw new Error("MCP OAuth authentication requires database");
}
registerMcpRoutes(app, {
  config,
  oauthConfig: mcpOAuthConfig,
  oauthVerifier: new McpOAuthVerifier(databasePool, mcpOAuthConfig),
  requestToolRegistryBuilder,
  auditLogger,
});

const shutdown = async () => {
  await app.close();
  await registry.close();
  userSyncConsumer?.stop();
  userLifecycleConsumer?.stop();
  r2AuditArchiver?.stop();

  // Graceful Audit Flush: Flush in-memory queue to PostgreSQL, then trigger final R2 upload
  try {
    await auditLogger?.flush();
    if (r2AuditArchiver) {
      await r2AuditArchiver.archivePendingLogs();
    }
  } catch (err) {
    console.error("Error during graceful audit log flush:", err);
  }

  auditLogger?.stop();
  await eventRedis?.quit();
  await lifecycleRedis?.quit();
  await redis?.quit();
  await databasePool?.end();
};

process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());

await app.listen({
  host: process.env.HOST ?? "0.0.0.0",
  port: Number(process.env.PORT ?? 3000),
});
