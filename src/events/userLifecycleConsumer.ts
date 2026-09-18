import type { Pool } from "pg";
import type { RedisClientType } from "redis";
import type { KeyVerifier } from "../auth/keyVerifier.js";
import { parseUserLifecycleEvent, type UserLifecycleEvent } from "./userLifecycleEvent.js";

const stream = "iam:events:user:v1";
const group = "tools-gateway-user-lifecycle-v1";
const dlq = `${stream}:tools-gateway:dlq`;
const maxAttempts = 5;

export async function applyUserLifecycleEvent(
  pool: Pool,
  verifier: Pick<KeyVerifier, "invalidateUser">,
  event: UserLifecycleEvent,
  expected: { issuer: string; tenantId: string },
  invalidateSessions: (subjectId: string) => Promise<void> = async () => undefined,
): Promise<boolean> {
  if (event.issuer !== expected.issuer || event.tenantId !== expected.tenantId) {
    // Other tenant events are acknowledged without local state changes
    return false;
  }
  const client = await pool.connect();
  let userId: string | undefined;
  let applied = false;
  try {
    await client.query("BEGIN");
    const receipt = await client.query(
      `INSERT INTO iam_user_lifecycle_events (event_id, tenant_id, subject_id, user_version)
       VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING RETURNING event_id`,
      [event.eventId, event.tenantId, event.subjectId, event.userVersion],
    );
    if (!receipt.rowCount) {
      await client.query("COMMIT");
      return false;
    }
    const status = event.eventType === "USER_DISABLED" ? "BLOCKED"
      : event.eventType === "USER_DELETED" ? "WITHDRAWN" : "ACTIVE";
    const state = await client.query(
      `INSERT INTO iam_user_lifecycle_states
         (tenant_id, subject_id, lifecycle_status, user_version, last_event_id)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (tenant_id, subject_id) DO UPDATE SET
         lifecycle_status = EXCLUDED.lifecycle_status,
         user_version = EXCLUDED.user_version,
         last_event_id = EXCLUDED.last_event_id,
         updated_at = NOW()
       WHERE iam_user_lifecycle_states.user_version < EXCLUDED.user_version
         AND iam_user_lifecycle_states.lifecycle_status <> 'WITHDRAWN'
       RETURNING subject_id`,
      [event.tenantId, event.subjectId, status, event.userVersion, event.eventId],
    );
    applied = Boolean(state.rowCount);
    if (applied && event.eventType === "USER_UPDATED" && event.profile) {
      await client.query(
        `UPDATE users SET email = $3, name = $4, user_version = $5, updated_at = NOW()
          WHERE tenant_id = $1 AND external_provider = 'snappytory_auth'
            AND external_subject_id = $2 AND user_version < $5`,
        [event.tenantId, event.subjectId, event.profile.email, event.profile.name, event.userVersion],
      );
    } else if (applied && event.eventType !== "USER_CREATED") {
      const updated = await client.query<{ id: string }>(
        `UPDATE users SET lifecycle_status = $3, is_active = ($3 = 'ACTIVE'),
                          user_version = $4, updated_at = NOW()
          WHERE tenant_id = $1 AND external_provider = 'snappytory_auth'
            AND external_subject_id = $2 AND user_version < $4
          RETURNING id`,
        [event.tenantId, event.subjectId, status, event.userVersion],
      );
      userId = updated.rows[0]?.id;
      if (userId && status !== "ACTIVE") {
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
  if (applied && event.eventType !== "USER_UPDATED" && event.eventType !== "USER_CREATED") {
    if (userId) await verifier.invalidateUser(userId);
    await invalidateSessions(event.subjectId);
  }
  return applied;
}

export class UserLifecycleConsumer {
  private running = false;
  constructor(
    private readonly redis: RedisClientType,
    private readonly pool: Pool,
    private readonly verifier: KeyVerifier,
    private readonly expected: { issuer: string; tenantId: string },
    private readonly consumerName = `gateway-lifecycle-${process.pid}`,
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
        await this.pool.query("UPDATE iam_user_lifecycle_health SET last_seen_at = NOW() WHERE singleton");
        for (const batch of batches ?? []) {
          for (const message of batch.messages) await this.process(message.id, message.message.data);
        }
      } catch (error) {
        if (this.running) console.error("user lifecycle consumer error", error);
      }
    }
  }

  private async process(id: string, data: string | undefined): Promise<void> {
    try {
      const event = parseUserLifecycleEvent(JSON.parse(data ?? "null"));
      await applyUserLifecycleEvent(this.pool, this.verifier, event, this.expected,
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
  }
}
