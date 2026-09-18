import { Pool } from "pg";
import { createClient, type RedisClientType } from "redis";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { EnsureLocalUserService } from "../src/users/ensureLocalUser.js";
import { applyUserLifecycleEvent, UserLifecycleConsumer } from "../src/events/userLifecycleConsumer.js";
import { parseUserLifecycleEvent } from "../src/events/userLifecycleEvent.js";

const databaseUrl = process.env.LIFECYCLE_INTEGRATION_DATABASE_URL;
const redisUrl = process.env.LIFECYCLE_INTEGRATION_REDIS_URL;
const integration = databaseUrl && redisUrl ? describe : describe.skip;
const expected = { issuer: "https://auth.example/t/tenant-a", tenantId: "tenant-a" };

integration("user lifecycle PostgreSQL/Redis integration", () => {
  const pool = new Pool({ connectionString: databaseUrl });
  const redis = createClient({ url: redisUrl! }) as RedisClientType;
  const verifier = { invalidateUser: vi.fn() };

  beforeAll(async () => {
    await redis.connect();
    await redis.flushDb();
    await pool.query(`
      DROP TABLE IF EXISTS api_keys, users, iam_user_lifecycle_states,
        iam_user_lifecycle_events, iam_user_lifecycle_health CASCADE;
      CREATE TABLE users (
        id text primary key, email text unique not null, name text not null,
        system_role text not null default 'USER', external_provider text,
        external_subject_id text, tenant_id text not null,
        lifecycle_status text not null default 'ACTIVE', user_version bigint not null default 1,
        is_active boolean not null default true, updated_at timestamptz not null default now()
      );
      CREATE UNIQUE INDEX idx_test_identity ON users(tenant_id, external_provider, external_subject_id)
        WHERE external_provider IS NOT NULL AND external_subject_id IS NOT NULL;
      CREATE TABLE api_keys (id text primary key, user_id text not null, is_active boolean not null default true);
      CREATE TABLE iam_user_lifecycle_states (
        tenant_id text not null, subject_id text not null, lifecycle_status text not null,
        user_version bigint not null, last_event_id text not null, updated_at timestamptz not null default now(),
        primary key(tenant_id, subject_id)
      );
      CREATE TABLE iam_user_lifecycle_events (
        event_id text primary key, tenant_id text not null, subject_id text not null,
        user_version bigint not null, processed_at timestamptz not null default now()
      );
      CREATE TABLE iam_user_lifecycle_health (
        singleton boolean primary key default true, last_seen_at timestamptz not null
      );
      INSERT INTO iam_user_lifecycle_health VALUES (true, now());
    `);
  });

  afterAll(async () => {
    await redis.quit();
    await pool.end();
  });

  it("keeps deleted terminal across duplicate and higher-version re-enable events", async () => {
    const deleted = parseUserLifecycleEvent({
      schema: "iam.user.v1", eventId: "evt-delete", eventType: "USER_DELETED",
      occurredAt: "2026-09-18T00:00:00Z", ...expected,
      subjectId: "iam-user-1", userVersion: 3,
    });
    const reenabled = parseUserLifecycleEvent({
      schema: "iam.user.v1", eventId: "evt-reenable", eventType: "USER_REENABLED",
      occurredAt: "2026-09-18T00:01:00Z", ...expected,
      subjectId: "iam-user-1", userVersion: 4,
    });

    await expect(applyUserLifecycleEvent(pool, verifier as never, deleted, expected)).resolves.toBe(true);
    await expect(applyUserLifecycleEvent(pool, verifier as never, deleted, expected)).resolves.toBe(false);
    await expect(applyUserLifecycleEvent(pool, verifier as never, reenabled, expected)).resolves.toBe(false);
    const state = await pool.query("SELECT lifecycle_status, user_version FROM iam_user_lifecycle_states");
    expect(state.rows).toEqual([{ lifecycle_status: "WITHDRAWN", user_version: "3" }]);
  });

  it("fails closed when the consumer heartbeat is older than 60 seconds", async () => {
    await pool.query("UPDATE iam_user_lifecycle_health SET last_seen_at = now() - interval '61 seconds'");
    const service = new EnsureLocalUserService(pool, "tenant-a");
    await expect(service.ensureLocalUser({
      tenantId: "tenant-a", subject: "new-user", email: "new@example.com", userVersion: 1,
    })).rejects.toThrow("inactive or token state is stale");
  });

  it("leaves a DB failure pending and succeeds on redelivery", async () => {
    const stream = "iam:events:user:v1";
    const group = "tools-gateway-user-lifecycle-v1";
    try { await redis.xGroupCreate(stream, group, "0", { MKSTREAM: true }); } catch {}
    const data = JSON.stringify({
      schema: "iam.user.v1", eventId: "evt-db-redelivery", eventType: "USER_DISABLED",
      occurredAt: "2026-09-18T00:02:00Z", ...expected,
      subjectId: "db-redelivery-user", userVersion: 2,
    });
    const id = await redis.xAdd(stream, "*", { data });
    await redis.xReadGroup(group, "db-failure", [{ key: stream, id: ">" }], { COUNT: 1 });
    const consumer = new UserLifecycleConsumer(redis, pool, verifier as never, expected, "db-redelivery");
    await pool.query("ALTER TABLE iam_user_lifecycle_events RENAME TO iam_user_lifecycle_events_unavailable");
    await (consumer as unknown as { process(id: string, data: string): Promise<void> }).process(id, data);
    const pendingAfterFailure = await redis.xPendingRange(stream, group, "-", "+", 10);
    expect(pendingAfterFailure.some((entry) => entry.id === id)).toBe(true);
    await pool.query("ALTER TABLE iam_user_lifecycle_events_unavailable RENAME TO iam_user_lifecycle_events");
    await (consumer as unknown as { process(id: string, data: string): Promise<void> }).process(id, data);
    const pendingAfterRetry = await redis.xPendingRange(stream, group, "-", "+", 10);
    expect(pendingAfterRetry.some((entry) => entry.id === id)).toBe(false);
  });

  it("reclaims a pending poison message and moves it to the service DLQ", async () => {
    const stream = "iam:events:user:v1";
    const group = "tools-gateway-user-lifecycle-v1";
    try { await redis.xGroupCreate(stream, group, "0", { MKSTREAM: true }); } catch {}
    const id = await redis.xAdd(stream, "*", { data: "not-json" });
    await redis.xReadGroup(group, "seed", [{ key: stream, id: ">" }], { COUNT: 1 });
    await redis.xClaim(stream, group, "seed", 0, id, { IDLE: 61_000 });
    await redis.set(`${group}:retry:${id}`, "4");
    const consumer = new UserLifecycleConsumer(redis, pool, verifier as never, expected, "integration-consumer");
    await consumer.start();
    let found = false;
    for (let attempt = 0; attempt < 30 && !found; attempt += 1) {
      const entries = await redis.xRange(`${stream}:tools-gateway:dlq`, "-", "+");
      found = entries.some((entry) => entry.message.sourceId === id);
      if (!found) await new Promise((resolve) => setTimeout(resolve, 100));
    }
    consumer.stop();
    expect(found).toBe(true);
  }, 10_000);
});
