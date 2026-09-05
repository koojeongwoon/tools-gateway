import { gzipSync } from "node:zlib";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import type { Pool } from "pg";
import type { R2AuditConfig } from "../config/r2.js";

export type { R2AuditConfig };

export interface ArchiveResult {
  archivedCount: number;
  key?: string | undefined;
}

export class R2AuditArchiver {
  private readonly s3Client?: S3Client;
  private timer?: NodeJS.Timeout | undefined;

  constructor(
    private readonly config: R2AuditConfig,
    private readonly pool: Pool,
    customS3Client?: S3Client,
  ) {
    if (config.enabled) {
      this.s3Client =
        customS3Client ??
        new S3Client({
          region: "auto",
          ...(config.endpoint ? { endpoint: config.endpoint } : {}),
          credentials: {
            accessKeyId: config.accessKeyId!,
            secretAccessKey: config.secretAccessKey!,
          },
        });
    }
  }

  start(): void {
    if (!this.config.enabled || this.timer) return;
    const interval = this.config.intervalMs ?? 3_600_000;
    this.timer = setInterval(() => {
      void this.archivePendingLogs().catch((error) => {
        console.error("[R2AuditArchiver] Background archive cycle failed:", error);
      });
    }, interval);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  async archivePendingLogs(): Promise<ArchiveResult> {
    if (!this.config.enabled || !this.s3Client) {
      return { archivedCount: 0 };
    }

    // Fetch batch of unarchived usage logs
    const result = await this.pool.query<Record<string, unknown>>(
      `SELECT * FROM tool_usage_logs
        WHERE r2_archived_at IS NULL
        ORDER BY created_at ASC
        LIMIT $1`,
      [this.config.batchSize],
    );

    const rows = result.rows;
    if (rows.length === 0) {
      return { archivedCount: 0 };
    }

    const ids = rows.map((row) => String(row.id));
    const now = new Date();
    const year = now.getUTCFullYear();
    const month = String(now.getUTCMonth() + 1).padStart(2, "0");
    const day = String(now.getUTCDate()).padStart(2, "0");
    const hour = String(now.getUTCHours()).padStart(2, "0");
    const timestamp = now.getTime();

    // Standardized WORM prefix: audit/{APP_NAME}/YYYY/MM/DD/HH-{timestamp}.jsonl.gz
    const key = `audit/${this.config.appName}/${year}/${month}/${day}/${hour}-${timestamp}.jsonl.gz`;

    // 1. Convert to JSONL format
    const jsonlString = rows.map((r) => JSON.stringify(r)).join("\n") + "\n";

    // 2. Compress to GZIP
    const compressed = gzipSync(Buffer.from(jsonlString, "utf8"));

    // 3. Upload to Cloudflare R2
    await this.s3Client.send(
      new PutObjectCommand({
        Bucket: this.config.bucketName,
        Key: key,
        Body: compressed,
        ContentType: "application/gzip",
      }),
    );

    // 4. Mark logs as archived in database
    await this.pool.query(
      `UPDATE tool_usage_logs
          SET r2_archived_at = NOW(),
              r2_archive_key = $2
        WHERE id = ANY($1::bigint[])`,
      [ids, key],
    );

    return {
      archivedCount: rows.length,
      key,
    };
  }
}
