import type { Pool } from "pg";

export interface ToolAuditLogEntry {
  userId: string;
  apiKeyId?: string | undefined;
  toolName: string;
  status: "SUCCESS" | "FORBIDDEN" | "ERROR";
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

export class AuditLogger {
  constructor(private readonly pool: Pool) {}

  async log(entry: ToolAuditLogEntry): Promise<void> {
    try {
      await this.pool.query(
        `INSERT INTO tool_usage_logs (
          user_id, api_key_id, tool_name, status, status_code, duration_ms,
          request_bytes, response_bytes, input_tokens, output_tokens, credits_used, arguments,
          ip_address, user_agent
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
        [
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
          entry.arguments ? JSON.stringify(entry.arguments) : null,
          isValidIp(entry.ipAddress) ? entry.ipAddress : null,
          entry.userAgent ?? null,
        ],
      );
    } catch (error) {
      // Audit logging should never break tool execution pipeline
      console.error("[AuditLogger] Failed to write tool usage log:", error);
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
  
  // Approximate BPE: split CJK and Latin characters
  let cjkCount = 0;
  let otherCount = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    // CJK Unified Ideographs, Hangul, Hiragana/Katakana
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
  // Base fixed cost per tool invocation (1.0 default)
  let baseCredit = 1.0;
  if (toolName.startsWith("hermes.")) {
    baseCredit = 5.0; // heavy browser execution
  } else if (toolName.startsWith("knowledge.")) {
    baseCredit = 2.0; // RAG / semantic search
  }

  // Variable cost: 0.0001 credit per KB
  const totalKb = (requestBytes + responseBytes) / 1024;
  const variableCredit = totalKb * 0.0001;

  return Number((baseCredit + variableCredit).toFixed(4));
}

function isValidIp(ip: string | undefined): boolean {
  if (!ip) return false;
  // Basic validation for IPv4 and IPv6 to prevent invalid INET casting in Postgres
  const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}
