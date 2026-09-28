import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Pool } from "pg";
import { randomUUID } from "node:crypto";
import { migrations } from "../src/database/migrations.js";
import { PostgresManagementStore } from "../src/daemonManagement/postgresStore.js";
import type { Identity, Report } from "../src/daemonManagement/model.js";
const url = process.env.DAEMON_MANAGEMENT_TEST_DATABASE;
describe.skipIf(!url)("daemon management real PostgreSQL", () => {
  const schema = `dm_${randomUUID().replaceAll("-", "")}`;
  const admin = new Pool({ connectionString: url });
  let pool: Pool, a: PostgresManagementStore, b: PostgresManagementStore;
  const i: Identity = { issuer: "https://iam.invalid/t/test", tenant: "test", subject: "owner", organization: "org", client: "daemon", resource: "https://gateway.invalid/api/v1/daemon-management", device: "device", version: 1, jkt: "key", userVersion: "1", serviceVersion: "1" };
  const report: Report = { schema_version: 1, report_id: "r1", sequence: 1, observed_at: new Date().toISOString(), status: { connection: "connected" } };
  beforeAll(async () => {
    await admin.query(`CREATE SCHEMA ${schema}`);
    pool = new Pool({ connectionString: url, options: `-c search_path=${schema}` });
    await pool.query(migrations.find(m => m.name === "daemon_management_reports")!.sql);
    a = new PostgresManagementStore(pool); b = new PostgresManagementStore(pool);
  });
  afterAll(async () => { await pool?.end(); await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); await admin.end(); });
  it("shares nonce binding and expiry across instances", async () => {
    const n = await a.issueNonce("gateway", "key");
    expect(await b.validNonce("gateway", "key", n)).toBe(true);
    expect(await b.validNonce("iam", "key", n)).toBe(false);
    expect(await b.validNonce("gateway", "other", n)).toBe(false);
    await pool.query("UPDATE daemon_management_nonces SET expires_at=clock_timestamp()-interval '1 second'");
    expect(await b.validNonce("gateway", "key", n)).toBe(false);
  });
  it("G03 accepts at most one concurrent proof across replicas", async () => {
    const results = await Promise.all(Array.from({length:20}, (_,n) => (n%2 ? a : b).consumeProof("gateway", "key", "one-proof")));
    expect(results.filter(Boolean)).toHaveLength(1);
  });
  it("G02 serializes reports, returns original receipt after ambiguous response, rejects altered content", async () => {
    const receipts = await Promise.all([a.accept(i, report), b.accept(i, report)]);
    expect(receipts[0]).toEqual(receipts[1]);
    // JSON field order is not a semantic change.
    expect(await b.accept(i, { ...report, status: { connection: "connected" } })).toEqual(receipts[0]);
    await expect(b.accept(i, { ...report, status: { connection: "unavailable" } })).rejects.toMatchObject({ status: 409 });
    await expect(b.accept(i, { ...report, report_id: "different" })).rejects.toMatchObject({ status: 409 });
    await expect(b.accept(i, { ...report, sequence: 2 })).rejects.toMatchObject({ status: 409 });
  });
  it("old sequence never replaces latest and tenant/subject cannot see each other", async () => {
    await a.accept(i, { ...report, report_id: "r3", sequence: 3 });
    await expect(b.accept(i, { ...report, report_id: "r2", sequence: 2 })).rejects.toMatchObject({ code: "report_out_of_order" });
    expect((await a.list(i.issuer, i.tenant, i.subject))[0]?.report.sequence).toBe(3);
    expect(await a.list(i.issuer, "other", i.subject)).toEqual([]);
    expect(await a.list(i.issuer, i.tenant, "other")).toEqual([]);
    await expect(a.accept({ ...i, subject: "other" }, { ...report, report_id: "r4", sequence: 4 })).rejects.toMatchObject({ status: 403 });
  });
});
