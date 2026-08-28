import Fastify from "fastify";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import { loadGatewayConfig } from "./config/upstreamConfig.js";
import { ToolPolicy } from "./policy/toolPolicy.js";
import { createGatewayServer } from "./server/createGatewayServer.js";
import { RemoteMcpConnection } from "./upstream/remoteMcpConnection.js";
import { ToolRegistry } from "./upstream/toolRegistry.js";

const configPath = process.env.UPSTREAM_CONFIG ?? "config/upstreams.yaml";
const config = await loadGatewayConfig(configPath);

const connections = [];
for (const upstream of config.upstreams.filter(({ enabled }) => enabled)) {
  connections.push(await RemoteMcpConnection.connect(upstream));
}

const registry = new ToolRegistry(connections);
await registry.refresh();
const policy = new ToolPolicy(config.toolPolicy);

const app = Fastify({ logger: true });

app.get("/healthz", async () => ({ status: "ok" }));
app.get("/readyz", async () => ({
  status: "ready",
  tools: registry.list().length,
}));

app.post("/mcp", async (request, reply) => {
  const server = createGatewayServer(registry, policy);
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
};

process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());

await app.listen({
  host: process.env.HOST ?? "0.0.0.0",
  port: Number(process.env.PORT ?? 3000),
});
