import { Pool, type PoolConfig } from "pg";
import { z } from "zod";

const databaseEnvironmentSchema = z.object({
  DATABASE_ENABLED: z.enum(["true", "false"]).default("false"),
  PGHOST: z.string().trim().min(1).optional(),
  PGPORT: z.coerce.number().int().min(1).max(65_535).default(5432),
  PGDATABASE: z.string().trim().min(1).optional(),
  PGUSER: z.string().trim().min(1).optional(),
  PGPASSWORD: z.string().min(1).optional(),
  PGPOOL_MAX: z.coerce.number().int().min(1).max(100).default(10),
  PGIDLE_TIMEOUT_MS: z.coerce.number().int().min(1_000).default(30_000),
  PGCONNECT_TIMEOUT_MS: z.coerce.number().int().min(1_000).default(5_000),
});

export interface DatabaseConfig {
  enabled: boolean;
  pool?: PoolConfig;
}

export function loadDatabaseConfig(
  environment: NodeJS.ProcessEnv = process.env,
): DatabaseConfig {
  const parsed = databaseEnvironmentSchema.parse(environment);
  if (parsed.DATABASE_ENABLED === "false") {
    return { enabled: false };
  }

  const required = ["PGHOST", "PGDATABASE", "PGUSER", "PGPASSWORD"] as const;
  for (const name of required) {
    if (!parsed[name]) {
      throw new Error(`${name} is required when DATABASE_ENABLED=true`);
    }
  }

  return {
    enabled: true,
    pool: {
      host: parsed.PGHOST,
      port: parsed.PGPORT,
      database: parsed.PGDATABASE,
      user: parsed.PGUSER,
      password: parsed.PGPASSWORD,
      max: parsed.PGPOOL_MAX,
      idleTimeoutMillis: parsed.PGIDLE_TIMEOUT_MS,
      connectionTimeoutMillis: parsed.PGCONNECT_TIMEOUT_MS,
      application_name: "tools-gateway",
    },
  };
}

export function createDatabasePool(config: DatabaseConfig): Pool | undefined {
  return config.enabled ? new Pool(config.pool) : undefined;
}
