import { randomUUID } from "node:crypto";
import { Pool } from "pg";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { migrations } from "../src/database/migrations.js";
import { EnsureLocalUserService } from "../src/users/ensureLocalUser.js";

const url = process.env.USER_IDENTITY_TEST_DATABASE;

describe.skipIf(!url)("verified SSO identity with production PostgreSQL column types", () => {
  const schema = `identity_${randomUUID().replaceAll("-", "")}`;
  const admin = new Pool({ connectionString: url });
  let pool: Pool;

  beforeAll(async () => {
    await admin.query(`CREATE SCHEMA ${schema}`);
    pool = new Pool({ connectionString: url, options: `-c search_path=${schema}` });
    for (const version of [1, 9, 10, 11, 12]) {
      await pool.query(migrations.find(migration => migration.version === version)!.sql);
    }
  });

  beforeEach(async () => {
    await pool.query("TRUNCATE users, iam_user_lifecycle_states, iam_user_service_access_states CASCADE");
    await pool.query("UPDATE iam_user_lifecycle_health SET last_seen_at = NOW()");
    await pool.query("UPDATE iam_user_service_access_health SET last_seen_at = NOW()");
  });

  afterAll(async () => {
    await pool?.end();
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    await admin.end();
  });

  it.each([false, true])("creates and updates a verified user with service enforcement=%s", async enforcement => {
    const service = new EnsureLocalUserService(pool, "tenant-a", {
      serviceAccessEnforcementEnabled: enforcement,
      clientId: "gateway",
    });
    const identity = {
      tenantId: "tenant-a", subject: "subject-a", email: "identity@example.invalid",
      name: "Initial", userVersion: 1, serviceAccessVersion: 1,
    };
    const id = await service.ensureLocalUser(identity);
    expect(await service.ensureLocalUser({ ...identity, name: "Updated", userVersion: 2 })).toBe(id);
    const saved = await pool.query("SELECT name, user_version FROM users WHERE id = $1", [id]);
    expect(saved.rows).toEqual([{ name: "Updated", user_version: "2" }]);

    await pool.query("UPDATE users SET lifecycle_status = 'BLOCKED' WHERE id = $1", [id]);
    await expect(service.ensureLocalUser(identity)).rejects.toThrow("inactive");
  });
});
