import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createDatabasePool, loadDatabaseConfig } from "../config/database.js";

const pool = createDatabasePool(loadDatabaseConfig());
if (!pool) throw new Error("DATABASE_ENABLED=true is required");

const rawKey = `tg_live_${randomBytes(32).toString("base64url")}`;
const hash = createHash("sha256").update(rawKey).digest("hex");
const keyId = `tg_key_${randomUUID()}`;
const client = await pool.connect();

try {
  await client.query("BEGIN");
  await client.query(
    `INSERT INTO user_service_permissions (id, user_id, service_name, allowed_actions)
     VALUES ($1, 'tg_usr_initial_admin', 'knowledge', '["read"]'::jsonb),
            ($2, 'tg_usr_initial_admin', 'context7', '["read"]'::jsonb)
     ON CONFLICT (user_id, service_name) DO NOTHING`,
    [`tg_perm_${randomUUID()}`, `tg_perm_${randomUUID()}`],
  );
  await client.query(
    `INSERT INTO api_keys (id, user_id, name, key_prefix, key_hash, allowed_scopes)
     VALUES ($1, 'tg_usr_initial_admin', $2, $3, $4,
             '["knowledge:read", "context7:read"]'::jsonb)`,
    [keyId, process.argv[2] ?? "initial-admin-cli", rawKey.slice(0, 16), hash],
  );
  await client.query("COMMIT");
  console.log("API key created. Store it now; it will not be shown again.");
  console.log(rawKey);
} catch (error) {
  await client.query("ROLLBACK");
  throw error;
} finally {
  client.release();
  await pool.end();
}
