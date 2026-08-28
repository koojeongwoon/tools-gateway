import type { Pool } from "pg";
import type { RedisClientType } from "redis";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import type { KeyVerifier } from "../auth/keyVerifier.js";

const eventSchema = z.object({
  schema: z.literal("auth.user.v1"),
  eventId: z.string().min(1),
  eventType: z.enum(["USER_CREATED", "USER_UPDATED", "USER_DISABLED", "USER_DELETED"]),
  occurredAt: z.iso.datetime(),
  subject: z.object({
    id: z.string().min(1),
    email: z.email(),
    name: z.string().min(1),
  }),
});

export type UserSyncEvent = z.infer<typeof eventSchema>;

export async function applyUserSyncEvent(
  pool: Pool,
  verifier: Pick<KeyVerifier, "invalidateUser">,
  input: unknown,
): Promise<void> {
  const event = eventSchema.parse(input);
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    if (event.eventType === "USER_CREATED" || event.eventType === "USER_UPDATED") {
      await client.query(
        `INSERT INTO users (id, email, name, external_provider, external_subject_id, is_active)
         VALUES ($1, $2, $3, 'snappytory_auth', $4, TRUE)
         ON CONFLICT (external_provider, external_subject_id)
           WHERE external_provider IS NOT NULL AND external_subject_id IS NOT NULL
         DO UPDATE SET email = EXCLUDED.email, name = EXCLUDED.name,
                       is_active = TRUE, updated_at = NOW()`,
        [`tg_usr_${event.subject.id}`, event.subject.email, event.subject.name, event.subject.id],
      );
      await client.query(
        `INSERT INTO user_service_permissions
           (id, user_id, service_name, allowed_actions)
         VALUES ($1, $2, 'knowledge', '["read"]'::jsonb)
         ON CONFLICT (user_id, service_name) DO NOTHING`,
        [`tg_perm_${randomUUID()}`, `tg_usr_${event.subject.id}`],
      );
    } else {
      await client.query(
        `UPDATE users SET is_active = FALSE, updated_at = NOW()
          WHERE external_provider = 'snappytory_auth' AND external_subject_id = $1`,
        [event.subject.id],
      );
      await client.query(
        `UPDATE api_keys SET is_active = FALSE
          WHERE user_id IN (SELECT id FROM users WHERE external_provider = 'snappytory_auth'
                            AND external_subject_id = $1)`,
        [event.subject.id],
      );
    }
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
  if (event.eventType === "USER_DISABLED" || event.eventType === "USER_DELETED") {
    await verifier.invalidateUser(`tg_usr_${event.subject.id}`);
  }
}

export class UserSyncConsumer {
  private running = false;
  constructor(
    private readonly redis: RedisClientType,
    private readonly pool: Pool,
    private readonly verifier: KeyVerifier,
    private readonly consumerName = `gateway-${process.pid}`,
  ) {}

  async start(): Promise<void> {
    try {
      await this.redis.xGroupCreate("auth:events", "tools-gateway-sync", "0", { MKSTREAM: true });
    } catch (error) {
      if (!(error instanceof Error) || !error.message.includes("BUSYGROUP")) throw error;
    }
    this.running = true;
    void this.loop();
  }

  stop(): void { this.running = false; }

  private async loop(): Promise<void> {
    while (this.running) {
      try {
        const streams = await this.redis.xReadGroup(
          "tools-gateway-sync", this.consumerName,
          [{ key: "auth:events", id: ">" }], { COUNT: 10, BLOCK: 5_000 },
        );
        for (const stream of streams ?? []) {
          for (const message of stream.messages) {
            try {
              const payload = JSON.parse(message.message.data ?? "null") as unknown;
              await applyUserSyncEvent(this.pool, this.verifier, payload);
              await this.redis.xAck("auth:events", "tools-gateway-sync", message.id);
            } catch (error) {
              if (error instanceof z.ZodError || error instanceof SyntaxError) {
                await this.redis.xAdd("auth:events:dlq", "*", {
                  sourceId: message.id, reason: "INVALID_EVENT",
                });
                await this.redis.xAck("auth:events", "tools-gateway-sync", message.id);
              }
            }
          }
        }
      } catch (error) {
        if (this.running) console.error("user sync consumer error", error);
      }
    }
  }
}
