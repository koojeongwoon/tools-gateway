import type { Pool } from "pg";
import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTVerifyGetKey,
} from "jose";
import type { AuthenticatedPrincipal } from "./scopeGuard.js";
import { EnsureLocalUserService } from "../users/ensureLocalUser.js";

export interface McpOAuthConfig {
  resource: string;
  resourceMetadataUrl: string;
  authorizationServer: string;
  issuer: string;
  jwksUri: string;
  tenantId: string;
  clientId: string;
  requiredScope: string;
  serviceAccessEnforcementEnabled: boolean;
}

export function loadMcpOAuthConfig(environment: NodeJS.ProcessEnv = process.env): McpOAuthConfig {
  const authServerUrl = (environment.AUTH_SERVER_URL ?? "https://auth.snappytory.com").replace(/\/$/, "");
  const tenantId = environment.TOOLS_GATEWAY_TENANT_ID ?? "ten_9664c024babc4110";
  const issuer = `${authServerUrl}/t/${tenantId}`;
  const configuredIssuer = environment.AUTH_TOKEN_ISSUER?.replace(/\/$/, "");
  if (configuredIssuer && configuredIssuer !== issuer) {
    throw new Error("AUTH_TOKEN_ISSUER must match the configured Tools Gateway tenant issuer");
  }
  const resource = new URL(environment.MCP_RESOURCE_URL ?? "https://tools-gateway.lynply.com/mcp");
  if (resource.search || resource.hash) {
    throw new Error("MCP_RESOURCE_URL must not contain a query string or fragment");
  }
  const metadataPath = `/.well-known/oauth-protected-resource${resource.pathname === "/" ? "" : resource.pathname}`;
  return {
    resource: resource.toString().replace(/\/$/, ""),
    resourceMetadataUrl: new URL(metadataPath, resource.origin).toString(),
    authorizationServer: issuer,
    issuer,
    jwksUri: `${issuer}/oauth2/jwks`,
    tenantId,
    clientId: environment.TOOLS_GATEWAY_CLIENT_ID ?? "tools-gateway-service",
    requiredScope: environment.MCP_OAUTH_SCOPE?.trim() || "mcp",
    serviceAccessEnforcementEnabled: environment.TOOLS_GATEWAY_SERVICE_ACCESS_ENFORCEMENT_ENABLED === "true",
  };
}

export class McpOAuthVerifier {
  private readonly jwks: JWTVerifyGetKey;

  constructor(
    private readonly pool: Pool,
    private readonly config: McpOAuthConfig,
    jwks: JWTVerifyGetKey = createRemoteJWKSet(new URL(config.jwksUri)),
  ) {
    this.jwks = jwks;
  }

  async verify(rawToken: string): Promise<AuthenticatedPrincipal | undefined> {
    try {
      const { payload } = await jwtVerify(rawToken, this.jwks, {
        issuer: this.config.issuer,
        audience: this.config.resource,
        algorithms: ["RS256"],
      });
      if (
        payload.tenant_id !== this.config.tenantId
        || typeof payload.sub !== "string"
        || payload.sub.length === 0
        || typeof payload.email !== "string"
        || payload.email.length === 0
        || !hasScope(payload.scope, this.config.requiredScope)
      ) {
        return undefined;
      }
      const userVersion = Number(payload.user_version ?? 1);
      if (!Number.isSafeInteger(userVersion) || userVersion < 1) return undefined;

      if (this.config.serviceAccessEnforcementEnabled) {
        const serviceAccessVersion = Number(payload.service_access_version);
        if (!Number.isSafeInteger(serviceAccessVersion) || serviceAccessVersion < 1) {
          return undefined;
        }
        const healthCheck = await this.pool.query(
          `SELECT 1 FROM iam_user_service_access_health
            WHERE singleton AND last_seen_at > NOW() - INTERVAL '60 seconds'`,
        );
        if (!healthCheck.rowCount) return undefined;

        const accessState = await this.pool.query(
          `SELECT 1 FROM iam_user_service_access_states
            WHERE tenant_id = $1 AND subject_id = $2 AND client_id = $3
              AND (service_access_status <> 'ACTIVE' OR access_version > $4)`,
          [this.config.tenantId, payload.sub, this.config.clientId, serviceAccessVersion],
        );
        if (accessState.rowCount && accessState.rowCount > 0) return undefined;
      }

      const userId = await new EnsureLocalUserService(this.pool, this.config.tenantId).ensureLocalUser({
        tenantId: payload.tenant_id,
        subject: payload.sub,
        email: payload.email,
        ...(typeof payload.name === "string" && payload.name ? { name: payload.name } : {}),
        userVersion,
      });

      const result = await this.pool.query<{
        user_id: string;
        system_role: string;
        tool_patterns: string[];
      }>(
        `SELECT u.id AS user_id, u.system_role,
                COALESCE(array_agg(DISTINCT p.tool_pattern)
                  FILTER (WHERE p.tool_pattern IS NOT NULL), ARRAY[]::text[])
                || COALESCE(array_agg(DISTINCT cu.tool_prefix || '.*')
                  FILTER (WHERE cu.tool_prefix IS NOT NULL), ARRAY[]::text[]) AS tool_patterns
           FROM users u
           LEFT JOIN user_tool_permissions p ON p.user_id = u.id
           LEFT JOIN user_mcp_upstreams cu ON cu.user_id = u.id AND cu.is_enabled
          WHERE u.id = $1
            AND u.is_active
            AND u.lifecycle_status = 'ACTIVE'
          GROUP BY u.id, u.system_role`,
        [userId],
      );
      const row = result.rows[0];
      if (!row) return undefined;
      return {
        userId: row.user_id,
        systemRole: row.system_role,
        toolPatterns: row.tool_patterns,
        scopes: row.tool_patterns.map((pattern) => `tool:${pattern}`),
      };
    } catch {
      return undefined;
    }
  }
}

function hasScope(claim: unknown, required: string): boolean {
  return typeof claim === "string" && claim.split(/\s+/).includes(required);
}
