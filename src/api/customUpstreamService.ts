import { randomUUID } from "node:crypto";
import type { Pool } from "pg";
import type { EnvelopeCrypto } from "../crypto/envelopeCrypto.js";

export interface CustomMcpUpstream {
  id: string;
  userId: string;
  toolPrefix: string;
  endpointUrl: string;
  transport: "streamable-http" | "sse";
  authType: "bearer" | "api_key" | "custom_header" | "none";
  authHeaderName: string;
  isEnabled: boolean;
  description?: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateCustomUpstreamDto {
  toolPrefix: string;
  endpointUrl: string;
  transport?: "streamable-http" | "sse" | undefined;
  authType?: "bearer" | "api_key" | "custom_header" | "none" | undefined;
  authHeaderName?: string | undefined;
  authValue?: string | undefined;
  description?: string | undefined;
}

export class CustomUpstreamService {
  constructor(
    private readonly pool: Pool,
    private readonly crypto: EnvelopeCrypto,
  ) {}

  async create(userId: string, dto: CreateCustomUpstreamDto): Promise<CustomMcpUpstream> {
    const id = `tg_ups_${randomUUID()}`;
    const transport = dto.transport ?? "streamable-http";
    const authType = dto.authType ?? (dto.authValue ? "bearer" : "none");
    const authHeaderName = dto.authHeaderName ?? (authType === "bearer" ? "Authorization" : "X-API-Key");

    let encryptedValue: string | null = null;
    let iv: string | null = null;
    let tag: string | null = null;

    if (authType !== "none") {
      if (!dto.authValue) {
        throw new Error("authValue is required when authType is not 'none'");
      }
      const enc = this.crypto.encrypt(dto.authValue);
      encryptedValue = enc.encryptedValue;
      iv = enc.iv;
      tag = enc.tag;
    }

    const result = await this.pool.query<CustomMcpUpstream>(
      `INSERT INTO user_mcp_upstreams (
         id, user_id, tool_prefix, endpoint_url, transport, auth_type,
         auth_header_name, encrypted_auth_value, encryption_iv, encryption_tag, description
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       RETURNING id, user_id as "userId", tool_prefix as "toolPrefix",
                 endpoint_url as "endpointUrl", transport, auth_type as "authType",
                 auth_header_name as "authHeaderName", is_enabled as "isEnabled",
                 description, created_at as "createdAt", updated_at as "updatedAt"`,
      [
        id,
        userId,
        dto.toolPrefix,
        dto.endpointUrl,
        transport,
        authType,
        authHeaderName,
        encryptedValue,
        iv,
        tag,
        dto.description ?? null,
      ],
    );

    const created = result.rows[0];
    if (!created) {
      throw new Error("Failed to insert custom MCP upstream");
    }
    return created;
  }

  async list(userId: string): Promise<CustomMcpUpstream[]> {
    const result = await this.pool.query<CustomMcpUpstream>(
      `SELECT id, user_id as "userId", tool_prefix as "toolPrefix",
              endpoint_url as "endpointUrl", transport, auth_type as "authType",
              auth_header_name as "authHeaderName", is_enabled as "isEnabled",
              description, created_at as "createdAt", updated_at as "updatedAt"
         FROM user_mcp_upstreams
        WHERE user_id = $1
        ORDER BY created_at DESC`,
      [userId],
    );
    return result.rows;
  }

  async delete(userId: string, upstreamId: string): Promise<boolean> {
    const result = await this.pool.query(
      "DELETE FROM user_mcp_upstreams WHERE id = $1 AND user_id = $2",
      [upstreamId, userId],
    );
    return Boolean(result.rowCount);
  }

  async getDecryptedAuthValue(userId: string, toolPrefix: string): Promise<{
    authType: string;
    authHeaderName: string;
    authValue?: string;
  } | undefined> {
    const result = await this.pool.query<{
      auth_type: string;
      auth_header_name: string;
      encrypted_auth_value: string | null;
      encryption_iv: string | null;
      encryption_tag: string | null;
    }>(
      `SELECT auth_type, auth_header_name, encrypted_auth_value, encryption_iv, encryption_tag
         FROM user_mcp_upstreams
        WHERE user_id = $1 AND tool_prefix = $2 AND is_enabled = TRUE`,
      [userId, toolPrefix],
    );

    const row = result.rows[0];
    if (!row) return undefined;

    if (row.auth_type === "none" || !row.encrypted_auth_value || !row.encryption_iv || !row.encryption_tag) {
      return { authType: row.auth_type, authHeaderName: row.auth_header_name };
    }

    const decrypted = this.crypto.decrypt({
      encryptedValue: row.encrypted_auth_value,
      iv: row.encryption_iv,
      tag: row.encryption_tag,
    });

    return {
      authType: row.auth_type,
      authHeaderName: row.auth_header_name,
      authValue: decrypted,
    };
  }
}
