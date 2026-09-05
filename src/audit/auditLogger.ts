import fs from "node:fs";
import path from "node:path";
import type { Pool } from "pg";
import { maskSensitiveArguments } from "../policy/toolArgumentSanitizer.js";

export interface ToolAuditLogEntry {
  requestId?: string | undefined;
  userId: string;
  apiKeyId?: string | undefined;
  toolName: string;
  status: "SUCCESS" | "FORBIDDEN" | "ERROR" | "SECURITY_VIOLATION";
  statusCode: number;
  durationMs: number;
  requestBytes?: number | undefined;
  responseBytes?: number | undefined;
  inputTokens?: number | undefined;
  outputTokens?: number | undefined;
  creditsUsed?: number | undefined;
  arguments?: Record<string, unknown> | undefined;
  ipAddress?: string | undefined;
  userAgent?: string | undefined;
}

export interface AuditLoggerOptions {
  /** Maximum number of logs to buffer before triggering a batch DB write (default: 50) */
  batchSize?: number;
  /** Maximum time in ms before buffered logs are written to DB (default: 1000ms) */
  flushIntervalMs?: number;
  /** Optional directory for fallback rolling log files when DB is unreachable (default: "logs") */
  fallbackLogDir?: string;
  /** Maximum in-memory retry queue size before discarding to prevent memory leak (default: 10000) */
  maxQueueSize?: number;
}

export class AuditLogger {
  private readonly batchSize: number;
  private readonly flushIntervalMs: number;
  private readonly fallbackLogDir: string;
  private readonly maxQueueSize: number;
  private queue: ToolAuditLogEntry[] = [];
  private timer?: NodeJS.Timeout | undefined;
  private isFlushing = false;

  constructor(
    private readonly pool: Pool,
    options?: AuditLoggerOptions,
  ) {
    this.batchSize = options?.batchSize ?? 50;
    this.flushIntervalMs = options?.flushIntervalMs ?? 1000;
    this.fallbackLogDir = options?.fallbackLogDir ?? "logs";
    this.maxQueueSize = options?.maxQueueSize ?? 10_000;
    this.startTimer();
  }

  private startTimer(): void {
    if (this.timer) return;
    this.timer = setInterval(() => {
      void this.flush();
    }, this.flushIntervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  /**
   * Non-blocking log submission.
   * Immediately buffers entry into memory and flushes if batch threshold is reached.
   */
  log(entry: ToolAuditLogEntry): void {
    this.queue.push(entry);
    if (this.queue.length >= this.batchSize) {
      void this.flush();
    }
  }

  /**
   * Flushes all in-memory queued audit logs to the PostgreSQL database in a single batch.
   */
  async flush(): Promise<void> {
    if (this.queue.length === 0 || this.isFlushing) return;
    this.isFlushing = true;

    const toProcess = this.queue;
    this.queue = [];

    try {
      // Build dynamic multi-row INSERT query for batch efficiency
      const valueRows: string[] = [];
      const values: unknown[] = [];
      let paramIndex = 1;

      for (const entry of toProcess) {
        const maskedArgs = entry.arguments ? maskSensitiveArguments(entry.arguments) : null;
        valueRows.push(
          `($${paramIndex}, $${paramIndex + 1}, $${paramIndex + 2}, $${paramIndex + 3}, $${paramIndex + 4}, $${paramIndex + 5}, $${paramIndex + 6}, $${paramIndex + 7}, $${paramIndex + 8}, $${paramIndex + 9}, $${paramIndex + 10}, $${paramIndex + 11}, $${paramIndex + 12}, $${paramIndex + 13}, $${paramIndex + 14})`,
        );
        values.push(
          entry.requestId ?? null,
          entry.userId,
          entry.apiKeyId ?? null,
          entry.toolName,
          entry.status,
          entry.statusCode,
          Math.max(0, Math.round(entry.durationMs)),
          Math.max(0, Math.round(entry.requestBytes ?? 0)),
          Math.max(0, Math.round(entry.responseBytes ?? 0)),
          Math.max(0, Math.round(entry.inputTokens ?? 0)),
          Math.max(0, Math.round(entry.outputTokens ?? 0)),
          entry.creditsUsed ?? 0.0,
          maskedArgs ? JSON.stringify(maskedArgs) : null,
          isValidIp(entry.ipAddress) ? entry.ipAddress : null,
          entry.userAgent ?? null,
        );
        paramIndex += 15;
      }

      await this.pool.query(
        `INSERT INTO tool_usage_logs (
          request_id, user_id, api_key_id, tool_name, status, status_code, duration_ms,
          request_bytes, response_bytes, input_tokens, output_tokens, credits_used, arguments,
          ip_address, user_agent
        ) VALUES ${valueRows.join(", ")}`,
        values,
      );
    } catch (error) {
      console.error("[AuditLogger] Failed to write batch tool usage logs to database:", error);
      this.writeFallbackFile(toProcess);

      // Re-queue failed batch at the beginning of the queue for retry if under maxQueueSize
      if (this.queue.length + toProcess.length <= this.maxQueueSize) {
        this.queue.unshift(...toProcess);
      } else {
        console.warn(`[AuditLogger] Queue limit reached (${this.maxQueueSize}). Evicting entries to fallback file only.`);
      }
    } finally {
      this.isFlushing = false;
    }
  }

  private writeFallbackFile(entries: ToolAuditLogEntry[]): void {
    try {
      if (!fs.existsSync(this.fallbackLogDir)) {
        fs.mkdirSync(this.fallbackLogDir, { recursive: true });
      }

      // Rolling daily file: audit-fallback-YYYY-MM-DD.jsonl
      const today = new Date().toISOString().slice(0, 10);
      const filePath = path.join(this.fallbackLogDir, `audit-fallback-${today}.jsonl`);

      const lines = entries
        .map((entry) =>
          JSON.stringify({
            ...entry,
            arguments: entry.arguments ? maskSensitiveArguments(entry.arguments) : undefined,
            failed_at: new Date().toISOString(),
          }),
        )
        .join("\n") + "\n";

      fs.appendFileSync(filePath, lines, "utf8");
    } catch (fallbackErr) {
      console.error("[AuditLogger] Failed to write fallback audit log file:", fallbackErr);
    }
  }
}

/**
 * Fast estimation of tokens for a given string or JSON payload.
 * Standard BPE average: ~4 characters per token for English/Code, ~1.5-2 for CJK.
 */
export function estimateTokens(textOrObject: unknown): number {
  if (textOrObject === undefined || textOrObject === null) return 0;
  const text = typeof textOrObject === "string" ? textOrObject : JSON.stringify(textOrObject);
  if (!text) return 0;

  let cjkCount = 0;
  let otherCount = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if ((code >= 0x4e00 && code <= 0x9fff) || (code >= 0xac00 && code <= 0xd7af) || (code >= 0x3040 && code <= 0x30ff)) {
      cjkCount++;
    } else {
      otherCount++;
    }
  }
  return Math.ceil(cjkCount * 0.7 + otherCount / 3.8);
}

/**
 * Calculates credit cost based on payload size and tool tier
 */
export function calculateCredits(toolName: string, requestBytes: number, responseBytes: number): number {
  let baseCredit = 1.0;
  if (toolName.startsWith("hermes.")) {
    baseCredit = 5.0;
  } else if (toolName.startsWith("knowledge.")) {
    baseCredit = 2.0;
  }

  const totalKb = (requestBytes + responseBytes) / 1024;
  const variableCredit = totalKb * 0.0001;

  return Number((baseCredit + variableCredit).toFixed(4));
}

function isValidIp(ip: string | undefined): boolean {
  if (!ip) return false;
  const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}
