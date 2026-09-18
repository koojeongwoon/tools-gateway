import type { Pool } from "pg";
import type { RedisClientType } from "redis";
import type { KeyVerifier } from "../auth/keyVerifier.js";
import { parseUserServiceAccessEvent, type UserServiceAccessEvent } from "./userServiceAccessEvent.js";

const stream = "iam:events:user-service-access:v1";
const group = "tools-gateway-service-access-v1";
const dlq = `${stream}:tools-gateway:dlq`;
const maxAttempts = 5;

export async function applyUserServiceAccessEvent(
  pool: Pool,
  verifier: Pick<KeyVerifier, "invalidateUser">,
  event: UserServiceAccessEvent,
  expected: { issuer: string; tenantId: string; clientId: string },
  invalidateSessions: (subjectId: string) => Promise<void> = async () => undefined,
): Promise<boolean> {
  if (event.issuer !== expected.issuer || event.tenantId !== expected.tenantId) {
    throw new Error("IAM service access event is outside the Gateway tenant boundary");
  }
  if (event.clientId !== expected.clientId) {
    // Other client events are acknowledged without local state changes
    return false;
  }
  const client = await pool.connect();
  let userId: string | undefined;
  let applied = false;
  try {
    await client.query("BEGIN");
    const receipt = await client.query(
      `INSERT INTO iam_user_service_access_events (event_id, tenant_id, subject_id, client_id, access_version)
       VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING RETURNING event_id`,
      [event.eventId, event.tenantId, event.subjectId, event.clientId, event.accessVersion],
    );
    if (!receipt.rowCount) {
      await client.query("COMMIT");
      return false;
    }
    const state = await client.query(
      `INSERT INTO iam_user_service_access_states
         (tenant_id, subject_id, client_id, service_access_status, access_version, last_event_id)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (tenant_id, subject_id, client_id) DO UPDATE SET
         service_access_status = EXCLUDED.service_access_status,
         access_version = EXCLUDED.access_version,
         last_event_id = EXCLUDED.last_event_id,
         updated_at = NOW()
       WHERE iam_user_service_access_states.access_version < EXCLUDED.access_version
         AND iam_user_service_access_states.service_access_status <> 'WITHDRAWN'
       RETURNING subject_id`,
      [event.tenantId, event.subjectId, event.clientId, event.status, event.accessVersion, event.eventId],
    );
    applied = Boolean(state.rowCount);
    if (applied && (event.status === "DISABLED" || event.status === "WITHDRAWN")) {
      const userRes = await client.query<{ id: string }>(
        `SELECT id FROM users
          WHERE tenant_id = $1 AND external_provider = 'snappytory_auth' AND external_subject_id = $2`,
        [event.tenantId, event.subjectId],
      );
      userId = userRes.rows[0]?.id;
      if (userId) {
        await client.query("UPDATE api_keys SET is_active = FALSE WHERE user_id = $1", [userId]);
      }
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  if (applied && (event.status === "DISABLED" || event.status === "WITHDRAWN")) {
    if (userId) await verifier.invalidateUser(userId);
    await invalidateSessions(event.subjectId);
  }
  return applied;
}

export class UserServiceAccessConsumer {
  private running = false;
  constructor(
    private readonly redis: RedisClientType,
    private readonly pool: Pool,
    private readonly verifier: KeyVerifier,
    private readonly expected: { issuer: string; tenantId: string; clientId: string },
    private readonly consumerName = `gateway-service-access-${process.pid}`,
  ) {}

  async start(): Promise<void> {
    try { await this.redis.xGroupCreate(stream, group, "0", { MKSTREAM: true }); }
    catch (error) { if (!(error instanceof Error) || !error.message.includes("BUSYGROUP")) throw error; }
    this.running = true;
    void this.loop();
  }

  stop(): void { this.running = false; }

  private async loop(): Promise<void> {
    while (this.running) {
      try {
        const claimed = await this.redis.xAutoClaim(stream, group, this.consumerName, 60_000, "0-0", { COUNT: 10 });
        for (const message of claimed.messages) {
          if (message) await this.process(message.id, message.message.data);
        }
        const batches = await this.redis.xReadGroup(
          group, this.consumerName, [{ key: stream, id: ">" }], { COUNT: 10, BLOCK: 5_000 },
        );
        await this.pool.query("UPDATE iam_user_service_access_health SET last_seen_at = NOW() WHERE singleton");
        for (const batch of batches ?? []) {
          for (const message of batch.messages) await this.process(message.id, message.message.data);
        }
      } catch (error) {
        if (this.running) console.error("user service access consumer error", error);
      }
    }
  }

  private async process(id: string, data: string | undefined): Promise<void> {
    try {
      const event = parseUserServiceAccessEvent(JSON.parse(data ?? "null"));
      await applyUserServiceAccessEvent(this.pool, this.verifier, event, this.expected,
        (subject) => this.invalidateSessions(subject));
      await this.redis.xAck(stream, group, id);
      await this.redis.del(`${group}:retry:${id}`);
    } catch (error) {
      const attempts = await this.redis.incr(`${group}:retry:${id}`);
      await this.redis.expire(`${group}:retry:${id}`, 86_400);
      if (attempts >= maxAttempts) {
        await this.redis.xAdd(dlq, "*", { sourceId: id, reason: error instanceof SyntaxError ? "INVALID_JSON" : "PROCESSING_FAILED" });
        await this.redis.xAck(stream, group, id);
      }
    }
  }

  private async invalidateSessions(subjectId: string): Promise<void> {
    const index = `tg:web:user:${subjectId}`;
    const keys = await this.redis.sMembers(index);
    if (keys.length) await this.redis.del(keys);
    await this.redis.del(index);
    // Also set user revocation key in Redis
    await this.redis.set(`auth:blacklist:user:${subjectId}`, "revoked", { EX: 86_400 });
  }
}
