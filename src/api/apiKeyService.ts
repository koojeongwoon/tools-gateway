import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Pool } from "pg";
import type { KeyVerifier } from "../auth/keyVerifier.js";
import type { GatewaySession } from "../auth/oauthSession.js";
import { matchesToolPattern } from "../auth/scopeGuard.js";
import { EnsureLocalUserService } from "../users/ensureLocalUser.js";

export class ApiKeyScopeError extends Error {}

export class ApiKeyService {
  constructor(private readonly pool: Pool, private readonly keyVerifier: KeyVerifier) {}

  async ensureLocalUser(session: GatewaySession): Promise<string> {
    const expectedTenantId = process.env.TOOLS_GATEWAY_TENANT_ID ?? "ten_9664c024babc4110";
    return new EnsureLocalUserService(this.pool, expectedTenantId).ensureLocalUser({
      tenantId: session.tenantId,
      subject: session.subject,
      email: session.email,
      ...(session.name ? { name: session.name } : {}),
      userVersion: session.userVersion,
    });
  }

  async create(
    userId: string,
    name: string,
    expiresAt?: string,
    requestedToolPatterns?: readonly string[],
  ): Promise<Record<string, unknown>> {
    const rawKey = `tg_live_${randomBytes(32).toString("base64url")}`;
    const id = `tg_key_${randomUUID()}`;
    const permissions = await this.pool.query<{ tool_pattern: string; is_custom: boolean }>(
      `SELECT tool_pattern, FALSE AS is_custom
         FROM user_tool_permissions
        WHERE user_id = $1
       UNION ALL
       SELECT tool_prefix || '.*' AS tool_pattern, TRUE AS is_custom
         FROM user_mcp_upstreams
        WHERE user_id = $1 AND is_enabled
       ORDER BY tool_pattern`,
      [userId],
    );
    const grantedPatterns = permissions.rows.map(({ tool_pattern }) => tool_pattern);
    // A custom upstream is eligible only when the caller explicitly selects
    // it for this key. Existing keys and scope-less new keys retain their
    // original user-granted tool set.
    const defaultPatterns = permissions.rows
      .filter(({ is_custom }) => !is_custom)
      .map(({ tool_pattern }) => tool_pattern);
    const selectedPatterns = requestedToolPatterns
      ? [...new Set(requestedToolPatterns)]
      : defaultPatterns;
    if (selectedPatterns.some((pattern) => !grantedPatterns.some(
      (grantedPattern) => matchesToolPattern(grantedPattern, pattern),
    ))) {
      throw new ApiKeyScopeError("Requested API key scope is not granted to this user");
    }
    const scopes = selectedPatterns.map((pattern) => `tool:${pattern}`);
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
    const [services, tools, customUpstreams] = await Promise.all([
      this.pool.query("SELECT service_name, allowed_actions FROM user_service_permissions WHERE user_id = $1 ORDER BY service_name", [userId]),
      this.pool.query("SELECT tool_pattern FROM user_tool_permissions WHERE user_id = $1 ORDER BY tool_pattern", [userId]),
      this.pool.query("SELECT tool_prefix FROM user_mcp_upstreams WHERE user_id = $1 AND is_enabled ORDER BY tool_prefix", [userId]),
    ]);
    return {
      services: services.rows,
      tools: tools.rows.map(({ tool_pattern }) => tool_pattern),
      customToolPatterns: customUpstreams.rows.map(({ tool_prefix }) => `${tool_prefix as string}.*`),
    };
  }
}
