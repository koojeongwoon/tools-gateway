import { z } from "zod";

const r2EnvironmentSchema = z.object({
  R2_AUDIT_ENABLED: z.enum(["true", "false"]).default("false"),
  R2_ENDPOINT: z.string().trim().url().optional(),
  R2_ACCOUNT_ID: z.string().trim().min(1).optional(),
  R2_ACCESS_KEY_ID: z.string().trim().min(1).optional(),
  R2_SECRET_ACCESS_KEY: z.string().trim().min(1).optional(),
  AWS_ACCESS_KEY_ID: z.string().trim().min(1).optional(),
  AWS_SECRET_ACCESS_KEY: z.string().trim().min(1).optional(),
  R2_BUCKET_NAME: z.string().trim().default("backup"),
  APP_NAME: z.string().trim().default("tools-gateway"),
  R2_AUDIT_BATCH_SIZE: z.coerce.number().int().min(1).max(5000).default(500),
  R2_AUDIT_INTERVAL_MS: z.coerce.number().int().min(1000).default(3_600_000), // 1 hour default (3,600,000 ms)
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

  const endpoint =
    parsed.R2_ENDPOINT ??
    (parsed.R2_ACCOUNT_ID ? `https://${parsed.R2_ACCOUNT_ID}.r2.cloudflarestorage.com` : undefined);
  const accessKeyId = parsed.R2_ACCESS_KEY_ID ?? parsed.AWS_ACCESS_KEY_ID;
  const secretAccessKey = parsed.R2_SECRET_ACCESS_KEY ?? parsed.AWS_SECRET_ACCESS_KEY;

  if (!endpoint) {
    throw new Error("R2_ENDPOINT or R2_ACCOUNT_ID is required when R2_AUDIT_ENABLED=true");
  }
  if (!accessKeyId) {
    throw new Error("R2_ACCESS_KEY_ID or AWS_ACCESS_KEY_ID is required when R2_AUDIT_ENABLED=true");
  }
  if (!secretAccessKey) {
    throw new Error("R2_SECRET_ACCESS_KEY or AWS_SECRET_ACCESS_KEY is required when R2_AUDIT_ENABLED=true");
  }

  return {
    enabled: true,
    endpoint,
    accessKeyId,
    secretAccessKey,
    bucketName: parsed.R2_BUCKET_NAME,
    appName: parsed.APP_NAME,
    batchSize: parsed.R2_AUDIT_BATCH_SIZE,
    intervalMs: parsed.R2_AUDIT_INTERVAL_MS,
  };
}

