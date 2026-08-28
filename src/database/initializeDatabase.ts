import type { Pool, PoolClient } from "pg";
import { migrations } from "./migrations.js";

const migrationLockId = 1_984_071_522;

export async function initializeDatabase(pool: Pool): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("SELECT pg_advisory_lock($1)", [migrationLockId]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INT PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    const applied = await client.query<{ version: number }>(
      "SELECT version FROM schema_migrations",
    );
    const versions = new Set(applied.rows.map(({ version }) => version));

    for (const migration of migrations) {
      if (!versions.has(migration.version)) {
        await applyMigration(client, migration);
      }
    }

    await seedAdministrator(client);
    await client.query("SELECT 1");
  } finally {
    await client.query("SELECT pg_advisory_unlock($1)", [migrationLockId]);
    client.release();
  }
}

async function applyMigration(
  client: PoolClient,
  migration: (typeof migrations)[number],
): Promise<void> {
  await client.query("BEGIN");
  try {
    await client.query(migration.sql);
    await client.query(
      "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)",
      [migration.version, migration.name],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  }
}

async function seedAdministrator(client: PoolClient): Promise<void> {
  await client.query(
    `INSERT INTO users (
       id, email, name, system_role, tier, external_provider, external_subject_id
     ) VALUES ($1, $2, $3, 'ADMIN', 'ENTERPRISE', 'local', $4)
     ON CONFLICT DO NOTHING`,
    [
      "tg_usr_initial_admin",
      "admin@snappytory.com",
      "Tools Gateway Administrator",
      "initial-admin",
    ],
  );

  const result = await client.query<{ system_role: string }>(
    "SELECT system_role FROM users WHERE email = $1",
    ["admin@snappytory.com"],
  );
  if (result.rows[0]?.system_role !== "ADMIN") {
    throw new Error("initial administrator seed conflicts with a non-admin user");
  }
}
