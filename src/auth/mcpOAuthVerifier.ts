import type { Pool } from "pg";
import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTVerifyGetKey,
} from "jose";
import type { AuthenticatedPrincipal } from "./scopeGuard.js";

export interface McpOAuthConfig {
  resource: string;
  resourceMetadataUrl: string;
  authorizationServer: string;
  issuer: string;
  jwksUri: string;
  tenantId: string;
  requiredScope: string;
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
    requiredScope: environment.MCP_OAUTH_SCOPE?.trim() || "mcp",
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
        || !hasScope(payload.scope, this.config.requiredScope)
      ) {
        return undefined;
      }

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
          WHERE u.external_provider = 'snappytory_auth'
            AND u.external_subject_id = $1
            AND u.is_active
          GROUP BY u.id, u.system_role`,
        [payload.sub],
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
