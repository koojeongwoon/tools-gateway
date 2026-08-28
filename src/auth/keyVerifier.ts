import { createHash } from "node:crypto";
import type { Pool } from "pg";
import type { RedisClientType } from "redis";
import type { AuthenticatedPrincipal } from "./scopeGuard.js";

const cacheTtlSeconds = 60;

export class KeyVerifier {
  constructor(
    private readonly pool: Pool,
    private readonly redis: RedisClientType,
  ) {}

  async verify(rawKey: string): Promise<AuthenticatedPrincipal | undefined> {
    if (!rawKey.startsWith("tg_live_") || rawKey.length < 32) return undefined;
    const hash = createHash("sha256").update(rawKey).digest("hex");
    const cacheKey = `tg:auth:key:${hash}`;
    const cached = await this.redis.get(cacheKey);
    if (cached) return JSON.parse(cached) as AuthenticatedPrincipal;

    const prefix = rawKey.slice(0, 16);
    const result = await this.pool.query<{
      api_key_id: string;
      user_id: string;
      system_role: string;
      allowed_scopes: string[];
      permissions: Record<string, string[]>;
    }>(
      `SELECT k.id AS api_key_id, u.id AS user_id, u.system_role,
              k.allowed_scopes,
              COALESCE(jsonb_object_agg(p.service_name, p.allowed_actions)
                FILTER (WHERE p.service_name IS NOT NULL), '{}'::jsonb) AS permissions
         FROM api_keys k
         JOIN users u ON u.id = k.user_id
         LEFT JOIN user_service_permissions p ON p.user_id = u.id
        WHERE k.key_prefix = $1 AND k.key_hash = $2
          AND k.is_active AND u.is_active
          AND (k.expires_at IS NULL OR k.expires_at > NOW())
        GROUP BY k.id, u.id, u.system_role, k.allowed_scopes`,
      [prefix, hash],
    );
    const row = result.rows[0];
    if (!row) return undefined;
    const principal: AuthenticatedPrincipal = {
      userId: row.user_id,
      apiKeyId: row.api_key_id,
      systemRole: row.system_role,
      scopes: row.allowed_scopes,
      permissions: row.permissions,
    };
    await this.redis.set(cacheKey, JSON.stringify(principal), { EX: cacheTtlSeconds });
    await this.redis.sAdd(`tg:auth:user:${principal.userId}`, cacheKey);
    await this.redis.expire(`tg:auth:user:${principal.userId}`, cacheTtlSeconds + 5);
    return principal;
  }

  async invalidateUser(userId: string): Promise<void> {
    const index = `tg:auth:user:${userId}`;
    const keys = await this.redis.sMembers(index);
    if (keys.length > 0) await this.redis.del(keys);
    await this.redis.del(index);
  }
}

export function bearerToken(header: string | string[] | undefined): string | undefined {
  if (typeof header !== "string") return undefined;
  const match = /^Bearer ([^\s]+)$/.exec(header);
  return match?.[1];
}
