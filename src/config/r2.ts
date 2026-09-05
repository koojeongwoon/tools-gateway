import { z } from "zod";

const r2EnvironmentSchema = z.object({
  R2_AUDIT_ENABLED: z.enum(["true", "false"]).default("false"),
  R2_ENDPOINT: z.string().trim().url().optional(),
  R2_ACCESS_KEY_ID: z.string().trim().min(1).optional(),
  R2_SECRET_ACCESS_KEY: z.string().trim().min(1).optional(),
  R2_BUCKET_NAME: z.string().trim().default("backup"),
  APP_NAME: z.string().trim().default("tools-gateway"),
  R2_AUDIT_BATCH_SIZE: z.coerce.number().int().min(1).max(5000).default(500),
  R2_AUDIT_INTERVAL_MS: z.coerce.number().int().min(1000).default(60_000), // 1 minute default
});

export interface R2AuditConfig {
  enabled: boolean;
  endpoint?: string | undefined;
  accessKeyId?: string | undefined;
  secretAccessKey?: string | undefined;
  bucketName: string;
  appName: string;
  batchSize: number;
  intervalMs?: number | undefined;
}

export function loadR2AuditConfig(
  environment: NodeJS.ProcessEnv = process.env,
): R2AuditConfig {
  const parsed = r2EnvironmentSchema.parse(environment);
  if (parsed.R2_AUDIT_ENABLED === "false") {
    return {
      enabled: false,
      bucketName: parsed.R2_BUCKET_NAME,
      appName: parsed.APP_NAME,
      batchSize: parsed.R2_AUDIT_BATCH_SIZE,
      intervalMs: parsed.R2_AUDIT_INTERVAL_MS,
    };
  }

  const required = ["R2_ENDPOINT", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY"] as const;
  for (const name of required) {
    if (!parsed[name]) {
      throw new Error(`${name} is required when R2_AUDIT_ENABLED=true`);
    }
  }

  return {
    enabled: true,
    endpoint: parsed.R2_ENDPOINT,
    accessKeyId: parsed.R2_ACCESS_KEY_ID,
    secretAccessKey: parsed.R2_SECRET_ACCESS_KEY,
    bucketName: parsed.R2_BUCKET_NAME,
    appName: parsed.APP_NAME,
    batchSize: parsed.R2_AUDIT_BATCH_SIZE,
    intervalMs: parsed.R2_AUDIT_INTERVAL_MS,
  };
}
