import type { FastifyInstance } from "fastify";
import type { GatewaySession } from "../auth/oauthSession.js";
import type { ManagementConfig } from "./config.js";
import { freshness, ManagementError, reportSchema, unavailable, type DeviceAuthorizer, type ManagementStore } from "./model.js";
import type { ManagementVerifier } from "./verifier.js";

export function registerDaemonManagementRoutes(app: FastifyInstance, config: ManagementConfig,
  verifier: ManagementVerifier, authorizer: DeviceAuthorizer, store: ManagementStore,
  resolveSession: (id: string) => Promise<GatewaySession | undefined>) {
  app.post("/api/v1/daemon-management/reports", { bodyLimit: 16384 }, async (request, reply) => {
    reply.header("cache-control", "no-store");
    try {
      const identity = await verifier.verify(request.headers.authorization, request.headers.dpop);
      await authorizer.authorize(identity);
      const parsed = reportSchema.safeParse(request.body);
      if (!parsed.success || Date.parse(parsed.data.observed_at) > Date.now() + 5000) throw new ManagementError(400, "invalid_report");
      return reply.code(202).send(await store.accept(identity, parsed.data));
    } catch (error) {
      const e = error instanceof ManagementError ? error : unavailable();
      if (e.status === 401) reply.header("www-authenticate", `DPoP error="${e.code}"`);
      if (e.nonce) reply.header("dpop-nonce", e.nonce);
      return reply.code(e.status).send({ error: e.code });
    }
  });
  // Only the IAM subject's own reports; no inferred organization-admin privileges.
  app.get("/api/v1/daemon-management/devices", async (request, reply) => {
    reply.header("cache-control", "no-store");
    try {
      const raw = request.headers.cookie?.split(";").map(s => s.trim()).find(s => s.startsWith("tg_session="))?.slice(11);
      const session = raw ? await resolveSession(decodeURIComponent(raw)) : undefined;
      if (!session || session.tenantId !== config.tenant) return reply.code(401).send({ error: "unauthorized" });
      const records = await store.list(config.issuer, config.tenant, session.subject);
      const devices = await Promise.all(records.map(async record => {
        let authorization: "authorized" | "denied" | "unknown" = "authorized";
        try { await authorizer.authorize(record.identity); }
        catch (error) { authorization = error instanceof ManagementError && error.status === 403 ? "denied" : "unknown"; }
        return { device_id: record.identity.device, organization_id: record.identity.organization,
          device_version: record.identity.version, authorization, freshness: freshness(record),
          report: record.report, receipt: record.receipt };
      }));
      return { schema_version: 1, devices };
    } catch { return reply.code(503).send({ error: "authorization_state_unavailable" }); }
  });
}
