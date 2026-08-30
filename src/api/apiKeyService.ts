import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Pool } from "pg";
import type { KeyVerifier } from "../auth/keyVerifier.js";
import type { GatewaySession } from "../auth/oauthSession.js";

export class ApiKeyService {
  constructor(private readonly pool: Pool, private readonly keyVerifier: KeyVerifier) {}

  async provisionUser(session: GatewaySession): Promise<string> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const existing = await client.query<{ id: string; is_active: boolean }>(
        `SELECT id, is_active FROM users
          WHERE (external_provider = 'snappytory_auth' AND external_subject_id = $1)
             OR ($2::text IS NOT NULL AND email = $2)
          ORDER BY CASE WHEN external_subject_id = $1 THEN 0 ELSE 1 END
          LIMIT 1 FOR UPDATE`,
        [session.subject, session.email ?? null],
      );
      if (existing.rows[0] && !existing.rows[0].is_active) {
        throw new Error("Tools Gateway user is inactive");
      }
      const id = existing.rows[0]?.id ?? `tg_usr_${randomUUID()}`;
      if (existing.rowCount) {
        await client.query(
          `UPDATE users SET email = COALESCE($2, email), name = COALESCE($3, name), external_provider = 'snappytory_auth',
                  external_subject_id = $4, updated_at = NOW()
            WHERE id = $1`,
          [id, session.email ?? null, session.name ?? null, session.subject],
        );
      } else {
        if (!session.email) {
          throw new Error("OIDC token is missing required 'email' claim");
        }
        await client.query(
          `INSERT INTO users (id, email, name, external_provider, external_subject_id)
           VALUES ($1, $2, $3, 'snappytory_auth', $4)`,
          [id, session.email, session.name ?? session.email, session.subject],
        );
      }
      await client.query("COMMIT");
      return id;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }

  async create(userId: string, name: string, expiresAt?: string): Promise<Record<string, unknown>> {
    const rawKey = `tg_live_${randomBytes(32).toString("base64url")}`;
    const id = `tg_key_${randomUUID()}`;
    const permissions = await this.pool.query<{ tool_pattern: string }>(
      "SELECT tool_pattern FROM user_tool_permissions WHERE user_id = $1 ORDER BY tool_pattern",
      [userId],
    );
    const scopes = permissions.rows.map(({ tool_pattern }) => `tool:${tool_pattern}`);
    const result = await this.pool.query(
      `INSERT INTO api_keys (id, user_id, name, key_prefix, key_hash, allowed_scopes, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
       RETURNING id, name, key_prefix, allowed_scopes, expires_at, created_at`,
      [id, userId, name, rawKey.slice(0, 16), createHash("sha256").update(rawKey).digest("hex"), JSON.stringify(scopes), expiresAt ?? null],
    );
    return { plainKey: rawKey, apiKey: result.rows[0] };
  }

  async list(userId: string): Promise<unknown[]> {
    const result = await this.pool.query(
      `SELECT id, name, key_prefix, allowed_scopes, is_active, expires_at, last_used_at, created_at
         FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC`,
      [userId],
    );
    return result.rows;
  }

  async revoke(userId: string, keyId: string): Promise<boolean> {
    const result = await this.pool.query(
      `UPDATE api_keys SET is_active = FALSE
        WHERE id = $1 AND user_id = $2 AND is_active
        RETURNING id`,
      [keyId, userId],
    );
    if (result.rowCount) await this.keyVerifier.invalidateUser(userId);
    return Boolean(result.rowCount);
  }

  async permissions(userId: string): Promise<unknown> {
    const [services, tools] = await Promise.all([
      this.pool.query("SELECT service_name, allowed_actions FROM user_service_permissions WHERE user_id = $1 ORDER BY service_name", [userId]),
      this.pool.query("SELECT tool_pattern FROM user_tool_permissions WHERE user_id = $1 ORDER BY tool_pattern", [userId]),
    ]);
    return { services: services.rows, tools: tools.rows.map(({ tool_pattern }) => tool_pattern) };
  }
}
