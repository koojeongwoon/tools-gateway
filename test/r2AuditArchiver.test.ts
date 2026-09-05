import { describe, it, expect, vi, beforeEach } from "vitest";
import { R2AuditArchiver, type R2AuditConfig } from "../src/audit/r2AuditArchiver.js";
import type { Pool } from "pg";

describe("R2AuditArchiver (Cloudflare R2 WORM Immutability Archiver)", () => {
  let mockPool: any;
  let mockS3Send: any;
  const config: R2AuditConfig = {
    enabled: true,
    endpoint: "https://test-account.r2.cloudflarestorage.com",
    accessKeyId: "test-access-key",
    secretAccessKey: "test-secret-key",
    bucketName: "backup",
    appName: "tools-gateway",
    batchSize: 100,
  };

  beforeEach(() => {
    mockPool = {
      query: vi.fn(),
    };
    mockS3Send = vi.fn().mockResolvedValue({});
  });

  it("should do nothing if R2 audit archiving is disabled", async () => {
    const disabledConfig: R2AuditConfig = { ...config, enabled: false };
    const archiver = new R2AuditArchiver(disabledConfig, mockPool as Pool);
    const result = await archiver.archivePendingLogs();

    expect(result.archivedCount).toBe(0);
    expect(mockPool.query).not.toHaveBeenCalled();
  });

  it("should archive unarchived logs, format JSONL, compress with GZIP, and upload with audit/ prefix", async () => {
    // Mock DB returning 2 unarchived logs
    const mockRows = [
      {
        id: "101",
        user_id: "user-1",
        tool_name: "github.get_file",
        status: "SUCCESS",
        status_code: 200,
        duration_ms: 15,
        created_at: new Date("2026-09-05T12:00:00Z"),
      },
      {
        id: "102",
        user_id: "user-2",
        tool_name: "knowledge.search",
        status: "SUCCESS",
        status_code: 200,
        duration_ms: 45,
        created_at: new Date("2026-09-05T12:01:00Z"),
      },
    ];

    mockPool.query
      .mockResolvedValueOnce({ rows: mockRows }) // fetch unarchived logs
      .mockResolvedValueOnce({ rowCount: 2 }); // mark as archived

    const archiver = new R2AuditArchiver(config, mockPool as Pool, {
      send: mockS3Send,
    } as any);

    const result = await archiver.archivePendingLogs();

    expect(result.archivedCount).toBe(2);
    expect(result.key).toContain("audit/tools-gateway/");
    expect(result.key).toMatch(/\.jsonl\.gz$/);

    // Verify S3 PutObjectCommand parameters
    expect(mockS3Send).toHaveBeenCalledTimes(1);
    const sendArgs = mockS3Send.mock.calls[0][0].input;
    expect(sendArgs.Bucket).toBe("backup");
    expect(sendArgs.Key).toBe(result.key);
    expect(sendArgs.ContentType).toBe("application/gzip");
    expect(sendArgs.Body).toBeInstanceOf(Buffer);

    // Verify database was updated to mark logs as archived
    expect(mockPool.query).toHaveBeenCalledWith(
      expect.stringContaining("UPDATE tool_usage_logs"),
      expect.arrayContaining([["101", "102"], result.key]),
    );
  });

  it("should handle empty pending logs gracefully", async () => {
    mockPool.query.mockResolvedValueOnce({ rows: [] });

    const archiver = new R2AuditArchiver(config, mockPool as Pool, {
      send: mockS3Send,
    } as any);

    const result = await archiver.archivePendingLogs();
    expect(result.archivedCount).toBe(0);
    expect(mockS3Send).not.toHaveBeenCalled();
  });
});
