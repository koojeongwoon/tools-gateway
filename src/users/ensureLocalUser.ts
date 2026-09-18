import { randomUUID } from "node:crypto";
import type { Pool } from "pg";

export interface VerifiedUserIdentity {
  tenantId: string;
  subject: string;
  email: string;
  name?: string;
  userVersion: number;
  serviceAccessVersion?: number;
}

export class EnsureLocalUserService {
  private readonly serviceAccessEnforcementEnabled: boolean;
  private readonly clientId: string;

  constructor(
    private readonly pool: Pool,
    private readonly expectedTenantId: string,
    options?: { serviceAccessEnforcementEnabled?: boolean; clientId?: string },
  ) {
    this.serviceAccessEnforcementEnabled = options?.serviceAccessEnforcementEnabled
      ?? (process.env.TOOLS_GATEWAY_SERVICE_ACCESS_ENFORCEMENT_ENABLED === "true");
    this.clientId = options?.clientId
      ?? (process.env.TOOLS_GATEWAY_CLIENT_ID ?? "tools-gateway-service");
  }

  async ensureLocalUser(identity: VerifiedUserIdentity): Promise<string> {
    if (
      identity.tenantId !== this.expectedTenantId
      || !identity.subject
      || !identity.email
      || !Number.isSafeInteger(identity.userVersion)
      || identity.userVersion < 1
    ) {
      throw new Error("Verified user identity does not belong to Tools Gateway");
    }
    if (this.serviceAccessEnforcementEnabled) {
      if (
        !Number.isSafeInteger(identity.serviceAccessVersion)
        || (identity.serviceAccessVersion ?? 0) < 1
      ) {
        throw new Error("Token is missing required service_access_version claim");
      }
    }
    const id = `tg_usr_${randomUUID()}`;
    const query = this.serviceAccessEnforcementEnabled
      ? `INSERT INTO users (
           id, email, name, external_provider, external_subject_id,
           tenant_id, lifecycle_status, user_version
         ) SELECT $1, $2, $3, 'snappytory_auth', $4, $5, 'ACTIVE', $6
         WHERE NOT EXISTS (
           SELECT 1 FROM iam_user_lifecycle_states s
            WHERE s.tenant_id = $5 AND s.subject_id = $4
              AND (s.lifecycle_status <> 'ACTIVE' OR s.user_version > $6)
         )
         AND EXISTS (
           SELECT 1 FROM iam_user_lifecycle_health
            WHERE singleton AND last_seen_at > NOW() - INTERVAL '60 seconds'
         )
         AND NOT EXISTS (
           SELECT 1 FROM iam_user_service_access_states a
            WHERE a.tenant_id = $5 AND a.subject_id = $4 AND a.client_id = $7
              AND (a.service_access_status <> 'ACTIVE' OR a.access_version > $8)
         )
         AND EXISTS (
           SELECT 1 FROM iam_user_service_access_health
            WHERE singleton AND last_seen_at > NOW() - INTERVAL '60 seconds'
         )
         ON CONFLICT (tenant_id, external_provider, external_subject_id)
           WHERE external_provider IS NOT NULL AND external_subject_id IS NOT NULL
         DO UPDATE SET
           email = EXCLUDED.email,
           name = EXCLUDED.name,
           user_version = GREATEST(users.user_version, EXCLUDED.user_version),
           updated_at = NOW()
         WHERE users.is_active AND users.lifecycle_status = 'ACTIVE'
         RETURNING id`
      : `INSERT INTO users (
           id, email, name, external_provider, external_subject_id,
           tenant_id, lifecycle_status, user_version
         ) SELECT $1, $2, $3, 'snappytory_auth', $4, $5, 'ACTIVE', $6
         WHERE NOT EXISTS (
           SELECT 1 FROM iam_user_lifecycle_states s
            WHERE s.tenant_id = $5 AND s.subject_id = $4
              AND (s.lifecycle_status <> 'ACTIVE' OR s.user_version > $6)
         )
         AND EXISTS (
           SELECT 1 FROM iam_user_lifecycle_health
            WHERE singleton AND last_seen_at > NOW() - INTERVAL '60 seconds'
         )
         ON CONFLICT (tenant_id, external_provider, external_subject_id)
           WHERE external_provider IS NOT NULL AND external_subject_id IS NOT NULL
         DO UPDATE SET
           email = EXCLUDED.email,
           name = EXCLUDED.name,
           user_version = GREATEST(users.user_version, EXCLUDED.user_version),
           updated_at = NOW()
         WHERE users.is_active AND users.lifecycle_status = 'ACTIVE'
         RETURNING id`;

    const params = this.serviceAccessEnforcementEnabled
      ? [id, identity.email, identity.name ?? identity.email, identity.subject, identity.tenantId, identity.userVersion, this.clientId, identity.serviceAccessVersion]
      : [id, identity.email, identity.name ?? identity.email, identity.subject, identity.tenantId, identity.userVersion];

    const result = await this.pool.query<{ id: string }>(query, params);
    const userId = result.rows[0]?.id;
    if (!userId) throw new Error("Tools Gateway user is inactive or token state is stale");
    return userId;
  }
}
