import type { Pool } from "pg";

export interface ToolAuditLogEntry {
  userId: string;
  apiKeyId?: string | undefined;
  toolName: string;
  status: "SUCCESS" | "FORBIDDEN" | "ERROR";
  statusCode: number;
  durationMs: number;
  ipAddress?: string | undefined;
  userAgent?: string | undefined;
}

export class AuditLogger {
  constructor(private readonly pool: Pool) {}

  async log(entry: ToolAuditLogEntry): Promise<void> {
    try {
      await this.pool.query(
        `INSERT INTO tool_usage_logs (
          user_id, api_key_id, tool_name, status, status_code, duration_ms, ip_address, user_agent
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
          entry.userId,
          entry.apiKeyId ?? null,
          entry.toolName,
          entry.status,
          entry.statusCode,
          Math.max(0, Math.round(entry.durationMs)),
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

function isValidIp(ip: string | undefined): boolean {
  if (!ip) return false;
  // Basic validation for IPv4 and IPv6 to prevent invalid INET casting in Postgres
  const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}
