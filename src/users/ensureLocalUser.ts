import { randomUUID } from "node:crypto";
import type { Pool } from "pg";

export interface VerifiedUserIdentity {
  tenantId: string;
  subject: string;
  email: string;
  name?: string;
  userVersion: number;
}

export class EnsureLocalUserService {
  constructor(private readonly pool: Pool, private readonly expectedTenantId: string) {}

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
    const id = `tg_usr_${randomUUID()}`;
    const result = await this.pool.query<{ id: string }>(
      `INSERT INTO users (
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
       RETURNING id`,
      [id, identity.email, identity.name ?? identity.email, identity.subject, identity.tenantId, identity.userVersion],
    );
    const userId = result.rows[0]?.id;
    if (!userId) throw new Error("Tools Gateway user is inactive or token state is stale");
    return userId;
  }
}
