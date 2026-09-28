import { JobSigner } from "../../src/daemonManagement/jobs/signer.js";
import { JobService } from "../../src/daemonManagement/jobs/service.js";
import { PostgresJobStore } from "../../src/daemonManagement/jobs/store.js";
import { registerJobRoutes } from "../../src/daemonManagement/jobs/routes.js";
// Isolated LM3-4 fixture; not a production entry point. All credentials synthetic.
import { readFileSync, existsSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash, generateKeyPairSync } from "node:crypto";
import Fastify from "fastify";
import { Pool } from "pg";
import { createClient } from "redis";
import { migrations } from "../../src/database/migrations.js";
import { ManagementVerifier } from "../../src/daemonManagement/verifier.js";
import { IamDeviceReader } from "../../src/daemonManagement/iamReader.js";
import { PostgresManagementStore } from "../../src/daemonManagement/postgresStore.js";
import { registerDaemonManagementRoutes } from "../../src/daemonManagement/routes.js";
import { OAuthSessionStore, loadOAuthConfig } from "../../src/auth/oauthSession.js";
import { DASHBOARD_HTML } from "../../src/ui/dashboardHtml.js";
const root = process.env.LM2_FIXTURE_ROOT!;
const pool = new Pool({ host: "127.0.0.1", port: 15432, database: "authdb", user: "sa", password: "lm34-test-only", options: "-c search_path=gateway_lm3_4" });
await pool.query("CREATE SCHEMA IF NOT EXISTS gateway_lm3_4");
const ready = await pool.query("SELECT to_regclass('daemon_management_heads') AS name");
if (!ready.rows[0].name) for(const name of ["daemon_management_reports","daemon_management_jobs","daemon_management_job_results"]) await pool.query(migrations.find(m=>m.name===name)!.sql);
const redis = createClient({ url: "redis://127.0.0.1:16379" }); await redis.connect();
const identity = JSON.parse(readFileSync(`${root}/public-identity.json`, "utf8"));
const config = { issuer: "https://localhost:19443/t/sk-telecom", tenant: "sk-telecom", resource: "https://localhost:19444/api/v1/daemon-management", client: "tools-daemon-management", readerClient: "tools-gateway-device-reader", readerSecret: "fixture-reader" };
// Only dashboard sessions are seeded; daemon token issuance and IAM authorization are real.
const sessions = new OAuthSessionStore(redis, loadOAuthConfig({ SSO_ENABLED: "true", AUTH_SERVER_URL: "https://localhost:19443", TOOLS_GATEWAY_TENANT_ID: "sk-telecom", TOOLS_GATEWAY_CLIENT_ID: "fixture-gateway-lm3-4", TOOLS_GATEWAY_CLIENT_SECRET: "fixture-gateway" })!);
for (const [id, subject] of [["fixture-owner", identity.subject], ["fixture-other", "different-subject"]]) {
  await redis.set(`tg:web:session:${createHash("sha256").update(id!).digest("hex")}`, JSON.stringify({ subject, tenantId: config.tenant, email: "fixture@example.invalid", userVersion: 1, expiresAt: Math.floor(Date.now()/1000)+600, iamAccessToken: "", iamAccessTokenExpiresAt: 0 }), { EX: 600 });
}
const app = Fastify({ logger: false, https: { key: readFileSync(`${root}/server.key`), cert: readFileSync(`${root}/server.pem`) } });
app.addHook("onSend", async (request, reply, payload) => {
  if (request.method === "POST" && request.url.endsWith("/reports") && reply.statusCode === 202 && existsSync(`${root}/drop-next-receipt`)) {
    unlinkSync(`${root}/drop-next-receipt`); request.raw.socket.destroy();
  }
  return payload;
});
const store = new PostgresManagementStore(pool);
const keyFile=`${root}/job-private.json`;
if(!existsSync(keyFile)) writeFileSync(keyFile,JSON.stringify({...generateKeyPairSync("ed25519").privateKey.export({format:"jwk"}),kid:"fixture-lm34"}),{mode:0o600});
const signer=await JobSigner.fromFile(keyFile);writeFileSync(`${root}/job-public.json`,JSON.stringify(signer.trust),{mode:0o600});
const reader=new IamDeviceReader(config),verifier=new ManagementVerifier(config,store);
const jobs=new JobService(config,new PostgresJobStore(pool),signer,{authority:(subject,organization)=>reader.authority(subject,organization,"fixture-gateway-lm3-4")},reader);
registerJobRoutes(app,config,jobs,verifier,id=>sessions.resolve(id));
registerDaemonManagementRoutes(app, config, new ManagementVerifier(config, store), new IamDeviceReader(config), store, id => sessions.resolve(id));
app.get("/", async (_req, reply) => reply.type("text/html").send(DASHBOARD_HTML));
app.get("/api/v1/auth/me", async () => ({ authenticated: true, user: { name: "LM3-4 검증 사용자" } }));
for (const route of ["keys", "upstreams", "permissions"]) app.get(`/api/v1/${route}`, async () => []);
app.get("/healthz", async () => ({status:"ok"}));
await app.listen({ host: "127.0.0.1", port: 19444 });
writeFileSync(`${root}/gateway-ready`, "ready");
process.on("SIGTERM", async () => { await app.close(); await pool.end(); await redis.quit(); process.exit(0); });
