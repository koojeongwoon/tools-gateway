import { beforeAll, describe, expect, it, vi } from "vitest";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, calculateJwkThumbprint } from "jose";
import Fastify from "fastify";
import { ManagementVerifier, hash } from "../src/daemonManagement/verifier.js";
import { IamDeviceReader } from "../src/daemonManagement/iamReader.js";
import { freshness, reportSchema, ManagementError, type Identity, type ManagementStore, type Report } from "../src/daemonManagement/model.js";
import { registerDaemonManagementRoutes } from "../src/daemonManagement/routes.js";
import type { GatewaySession } from "../src/auth/oauthSession.js";
import { loadManagementConfig } from "../src/daemonManagement/config.js";
const config = { issuer: "https://iam.example.invalid/t/tenant", tenant: "tenant", resource: "https://gateway.example.invalid/api/v1/daemon-management", client: "tools-daemon-management", readerClient: "tools-gateway-device-reader", readerSecret: "test-only" };
let rsa: Awaited<ReturnType<typeof generateKeyPair>>, ec: Awaited<ReturnType<typeof generateKeyPair>>;
let jwk: Awaited<ReturnType<typeof exportJWK>>, keys: ReturnType<typeof createLocalJWKSet>, jkt: string;
const now = Math.floor(Date.now()/1000);
const report: Report = { schema_version: 1, report_id: "report-1", sequence: 1, observed_at: new Date(now*1000).toISOString(), status: { connection: "connected" } };
const receipt = { report_id: report.report_id, sequence: 1, received_at: report.observed_at };
function store(): ManagementStore {
  const seen = new Set<string>();
  return { issueNonce: vi.fn(async () => "nonce"), validNonce: vi.fn(async (_v, _j, n) => n === "nonce"),
    consumeProof: vi.fn(async (_v, _j, id) => { if (seen.has(id)) return false; seen.add(id); return true; }),
    accept: vi.fn(async () => receipt), list: vi.fn(async () => []) };
}
async function credentials(tokenChanges = {}, proofChanges = {}, headerChanges = {}) {
  const token = await new SignJWT({ iss: config.issuer, aud: [config.resource], sub: "user", client_id: config.client, tenant_id: config.tenant,
    active_organization_id: "org", iat: now, exp: now+300, jti: "token", scope: "device:identity gateway:daemon:report",
    cnf: { jkt }, "https://lynply.com/claims/device": { v: 1, id: "device", version: 1 }, user_version: "1", service_access_version: "1", ...tokenChanges })
    .setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid: "iam" }).sign(rsa.privateKey);
  const proof = await new SignJWT({ jti: "proof", iat: now, htm: "POST", htu: `${config.resource}/reports`, ath: hash(token), nonce: "nonce", ...proofChanges })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk, ...headerChanges }).sign(ec.privateKey);
  return { token, proof };
}
async function identity(): Promise<Identity> { const c = await credentials(); return new ManagementVerifier(config, store(), keys, () => now*1000).verify(`DPoP ${c.token}`, c.proof); }
beforeAll(async () => {
  rsa = await generateKeyPair("RS256"); ec = await generateKeyPair("ES256");
  jwk = await exportJWK(ec.publicKey); jkt = await calculateJwkThumbprint(jwk);
  keys = createLocalJWKSet({ keys: [{ ...await exportJWK(rsa.publicKey), kid: "iam", alg: "RS256" }] });
});
describe("management authentication", () => {
  it("accepts only the registered key and management audience", async () => { expect((await identity()).device).toBe("device"); });
  it.each([
    ["issuer", { iss: "https://other.invalid" }], ["audience", { aud: "mcp" }], ["multiple audiences", { aud: [config.resource, "mcp"] }],
    ["tenant", { tenant_id: "other" }], ["client", { client_id: "other" }], ["no subject", { sub: "" }],
    ["expired", { exp: now }], ["future", { iat: now+6 }], ["long lifetime", { exp: now+301 }],
    ["organization", { active_organization_id: "" }], ["version", { user_version: 1 }],
    ["device", { "https://lynply.com/claims/device": { v: 2, id: "device", version: 1 } }],
    ["binding", { cnf: {} }],
  ])("rejects invalid %s", async (_name, changes) => {
    const c = await credentials(changes as object);
    await expect(new ManagementVerifier(config, store(), keys, () => now*1000).verify(`DPoP ${c.token}`, c.proof)).rejects.toMatchObject({ status: 401, code: "invalid_token" });
  });
  it("rejects scope omission", async () => {
    const c = await credentials({ scope: "openid" });
    await expect(new ManagementVerifier(config, store(), keys).verify(`DPoP ${c.token}`, c.proof)).rejects.toMatchObject({ status: 403 });
  });
  it.each([ ["method", { htm: "GET" }], ["path", { htu: `${config.resource}/other` }], ["hash", { ath: "bad" }],
    ["expired proof", { iat: now-61 }], ["future proof", { iat: now+6 }], ["missing jti", { jti: "" }] ])("rejects proof %s", async (_name, changes) => {
    const c = await credentials({}, changes as object);
    await expect(new ManagementVerifier(config, store(), keys, () => now*1000).verify(`DPoP ${c.token}`, c.proof)).rejects.toMatchObject({ code: "invalid_dpop_proof" });
  });
  it.each([{ typ: "JWT" }, { jku: "https://evil.invalid" }, { jwk: { kty: "EC", crv: "P-256", x: "bad", y: "bad", d: "secret" } }])("rejects unsafe JOSE header %j", async h => {
    const c = await credentials({}, {}, h);
    await expect(new ManagementVerifier(config, store(), keys).verify(`DPoP ${c.token}`, c.proof)).rejects.toMatchObject({ code: "invalid_dpop_proof" });
  });
  it("does not accept Bearer/session credentials or missing proof", async () => {
    const c = await credentials(), verifier = new ManagementVerifier(config, store(), keys);
    await expect(verifier.verify(`Bearer ${c.token}`, c.proof)).rejects.toMatchObject({ code: "invalid_token" });
    await expect(verifier.verify(undefined, c.proof)).rejects.toMatchObject({ code: "invalid_token" });
    await expect(verifier.verify(`DPoP ${c.token}`, undefined)).rejects.toMatchObject({ code: "invalid_dpop_proof" });
  });
  it("challenges separate Gateway nonce then prevents replay", async () => {
    const db = store(), verifier = new ManagementVerifier(config, db, keys);
    const wrong = await credentials({}, { nonce: "iam-nonce" });
    await expect(verifier.verify(`DPoP ${wrong.token}`, wrong.proof)).rejects.toMatchObject({ code: "use_dpop_nonce", nonce: "nonce" });
    expect(db.consumeProof).not.toHaveBeenCalled();
    const good = await credentials(); await verifier.verify(`DPoP ${good.token}`, good.proof);
    await expect(verifier.verify(`DPoP ${good.token}`, good.proof)).rejects.toMatchObject({ code: "invalid_dpop_proof" });
  });
  it("fails closed on shared replay storage outage", async () => {
    const db = store(); db.consumeProof = async () => { throw new Error("database secret"); };
    const c = await credentials();
    await expect(new ManagementVerifier(config, db, keys).verify(`DPoP ${c.token}`, c.proof)).rejects.toMatchObject({ status: 503, message: "authorization_state_unavailable" });
  });
});
describe("job delivery DPoP scope and route", () => {
  it("accepts only explicit jobs scope with GET proof bound to pending route", async () => {
    const c=await credentials({scope:"openid device:identity gateway:daemon:jobs:read"},{htm:"GET",htu:`${config.resource}/jobs/pending`});
    const verifier=new ManagementVerifier(config,store(),keys,()=>now*1000);
    expect((await verifier.verify(`DPoP ${c.token}`,c.proof,"jobs")).device).toBe("device");
    await expect(verifier.verify(`DPoP ${c.token}`,c.proof,"jobs")).rejects.toMatchObject({code:"invalid_dpop_proof"});
    await expect(verifier.verify(`DPoP ${c.token}`,c.proof,"report")).rejects.toMatchObject({code:"insufficient_scope"});
  });
  it("report-only token cannot fetch jobs even with a valid pending-route proof", async () => {
    const c=await credentials({},{htm:"GET",htu:`${config.resource}/jobs/pending`});
    await expect(new ManagementVerifier(config,store(),keys).verify(`DPoP ${c.token}`,c.proof,"jobs")).rejects.toMatchObject({code:"insufficient_scope"});
  });
  it("jobs token cannot reuse proof bound to report POST", async () => {
    const c=await credentials({scope:"openid device:identity gateway:daemon:jobs:read"});
    await expect(new ManagementVerifier(config,store(),keys).verify(`DPoP ${c.token}`,c.proof,"jobs")).rejects.toMatchObject({code:"invalid_dpop_proof"});
  });
});
describe("online IAM authorization", () => {
  async function fixture() {
    const i = await identity(); let time = 0;
    const status = { device_id: i.device, subject: i.subject, tenant_id: i.tenant, organization_id: i.organization, device_version: i.version, key_jkt: i.jkt, user_version: "1", service_access_version: "1", status: "ACTIVE", authorized: true, checked_at: now };
    const request = vi.fn(async (url: string) => new Response(JSON.stringify(url.endsWith("/token") ? { token_type: "Bearer", access_token: "reader-secret", expires_in: 300 } : status)));
    return { i, status, request, reader: new IamDeviceReader(config, request, () => time), tick: (t: number) => { time = t; } };
  }
  it("expires cached ACTIVE within 15s, denies revoked and never reuses expired cache during outage", async () => {
    const f = await fixture(); await f.reader.authorize(f.i); f.status.status = "REVOKED";
    f.tick(14999); await f.reader.authorize(f.i); expect(f.request).toHaveBeenCalledTimes(2);
    f.tick(15000); await expect(f.reader.authorize(f.i)).rejects.toMatchObject({ status: 403 });
    f.request.mockRejectedValue(new Error("offline"));
    await expect(f.reader.authorize(f.i)).rejects.toMatchObject({ status: 503 });
  });
  it("includes every identity version and key in cache binding", async () => {
    const f = await fixture(); await f.reader.authorize(f.i);
    for (const change of [{ device: "other" }, { subject: "other" }, { organization: "other" }, { version: 2 }, { jkt: "other" }, { userVersion: "2" }, { serviceVersion: "2" }]) {
      await expect(f.reader.authorize({ ...f.i, ...change })).rejects.toMatchObject({ status: 403 });
    }
  });
  it("subtracts lookup latency and denies backward monotonic clock", async () => {
    const f = await fixture(); const original = f.request.getMockImplementation()!;
    f.request.mockImplementation(async url => { const r = await original(url); f.tick(14000); return r; });
    await f.reader.authorize(f.i); f.tick(15000); f.status.authorized = false;
    await expect(f.reader.authorize(f.i)).rejects.toMatchObject({ status: 403 });
    const g = await fixture(); const fresh = g.request.getMockImplementation()!; g.request.mockImplementation(async url => { g.tick(-1); return fresh(url); });
    await expect(g.reader.authorize(g.i)).rejects.toMatchObject({ status: 503 });
  });
});
describe("reports and owner display", () => {
  it("accepts bounded observed revocation results without treating unknown as completed", () => {
    const result = {job_id: "job-1", digest: "a".repeat(64), resource_id: "worker-1",
      state_version: 2, admission: "blocked", termination: "unknown"};
    const payload = {...report, status: {...report.status, job_results: [result]}};
    expect(reportSchema.parse(payload).status.job_results?.[0]?.termination).toBe("unknown");
    for (const change of [{termination: "success"}, {admission: "allowed"}, {state_version: 0},
      {digest: "bad"}, {token: "secret"}, {path: "/arbitrary"}]) {
      expect(reportSchema.safeParse({...payload, status: {...payload.status, job_results: [{...result, ...change}]}}).success).toBe(false);
    }
    expect(reportSchema.safeParse({...payload, status: {...payload.status, job_results: Array(21).fill(result)}}).success).toBe(false);
  });
  it("allows bounded metadata, rejects arbitrary contents and future observation", () => {
    expect(reportSchema.safeParse(report).success).toBe(true);
    for (const status of [{ connection: "connected", path: "/secret" }, { connection: "connected", token: "secret" }, { connection: "connected", recent_events: Array(21).fill({}) }]) expect(reportSchema.safeParse({ ...report, status }).success).toBe(false);
  });
  it("never treats delayed old reports or clock errors as fresh", () => {
    const record = { identity: {} as Identity, report, receipt };
    expect(freshness(record, now*1000+90001)).toBe("stale");
    expect(freshness({ ...record, receipt: { ...receipt, received_at: new Date(now*1000+100000).toISOString() } }, now*1000+100000)).toBe("stale");
    expect(freshness(record, now*1000-6000)).toBe("stale");
  });
  it("authenticates reports independently of SSO, displays only owner's scoped records, hides authorization details", async () => {
    const db = store(), i = await identity(), auth = { authorize: vi.fn(async () => {}) };
    db.list = vi.fn(async () => [{ identity: i, report, receipt }]);
    const app = Fastify(); const session = { tenantId: "tenant", subject: "user" } as GatewaySession;
    registerDaemonManagementRoutes(app, config, new ManagementVerifier(config, db, keys), auth, db, async s => s === "valid" ? session : undefined);
    try {
      expect((await app.inject({ method: "POST", url: "/api/v1/daemon-management/reports", headers: { cookie: "tg_session=valid" }, payload: report })).statusCode).toBe(401);
      const c = await credentials(); const response = await app.inject({ method: "POST", url: "/api/v1/daemon-management/reports", headers: { authorization: `DPoP ${c.token}`, dpop: c.proof, host: "evil.invalid", forwarded: "host=evil.invalid" }, payload: { ...report, status: { ...report.status, job_results: [{job_id:"job-1", digest:"a".repeat(64), resource_id:"worker-1", state_version:2, admission:"blocked", termination:"unknown"}] } } });
      expect(db.accept).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({status:expect.objectContaining({job_results:expect.arrayContaining([expect.objectContaining({termination:"unknown"})])})}));
      expect(response.statusCode).toBe(202); expect(response.json()).toEqual(receipt);
      expect((await app.inject("/api/v1/daemon-management/devices")).statusCode).toBe(401);
      auth.authorize.mockRejectedValue(new ManagementError(403, "device_not_authorized"));
      const view = await app.inject({ url: "/api/v1/daemon-management/devices", headers: { cookie: "tg_session=valid" } });
      expect(db.list).toHaveBeenCalledWith(config.issuer, "tenant", "user");
      expect(view.json().devices[0].authorization).toBe("denied"); expect(view.body).not.toContain(jkt);
    } finally { await app.close(); }
  });
  it("is deployment opt-in and does not alter service enforcement", () => {
    expect(loadManagementConfig({})).toBeUndefined();
    expect(() => loadManagementConfig({ DAEMON_MANAGEMENT_ENABLED: "true" })).toThrow();
    expect(() => loadManagementConfig({ DAEMON_MANAGEMENT_ENABLED: "true", DAEMON_DEVICE_READER_SECRET: "test", DAEMON_MANAGEMENT_RESOURCE: "http://evil.invalid" })).toThrow();
  });
});
