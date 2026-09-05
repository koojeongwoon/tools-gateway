import fs from "node:fs";
import path from "node:path";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { AuditLogger, type ToolAuditLogEntry } from "../src/audit/auditLogger.js";
import type { Pool } from "pg";

describe("AuditLogger (In-Memory Queue Buffer, Traceability & Graceful Flush)", () => {
  let mockPool: any;

  beforeEach(() => {
    mockPool = {
      query: vi.fn().mockResolvedValue({ rowCount: 1 }),
    };
  });

  it("should buffer log entries in memory and flush in batch to database", async () => {
    const logger = new AuditLogger(mockPool as Pool, {
      batchSize: 2,
      flushIntervalMs: 10_000, // long interval to test size trigger
    });

    const entry1: ToolAuditLogEntry = {
      requestId: "req-12345",
      userId: "user-1",
      apiKeyId: "key-1",
      toolName: "github.get_file",
      status: "SUCCESS",
      statusCode: 200,
      durationMs: 15,
      ipAddress: "127.0.0.1",
      userAgent: "vitest",
    };

    const entry2: ToolAuditLogEntry = {
      requestId: "req-12345",
      userId: "user-1",
      apiKeyId: "key-1",
      toolName: "knowledge.search",
      status: "SUCCESS",
      statusCode: 200,
      durationMs: 30,
      ipAddress: "127.0.0.1",
      userAgent: "vitest",
    };

    // First entry: buffered, no DB query yet
    logger.log(entry1);
    expect(mockPool.query).not.toHaveBeenCalled();

    // Second entry reaches batchSize (2): triggers batch insert
    logger.log(entry2);
    // Allow microtask to process batch write
    await new Promise((resolve) => setTimeout(resolve, 10));

    expect(mockPool.query).toHaveBeenCalledTimes(1);
    expect(mockPool.query).toHaveBeenCalledWith(
      expect.stringContaining("INSERT INTO tool_usage_logs"),
      expect.arrayContaining(["req-12345", "user-1", "github.get_file"]),
    );

    logger.stop();
  });

  it("should flush remaining logs on timer interval", async () => {
    const logger = new AuditLogger(mockPool as Pool, {
      batchSize: 10,
      flushIntervalMs: 20, // fast interval
    });

    logger.log({
      requestId: "req-trace-999",
      userId: "user-2",
      toolName: "context7.query",
      status: "SUCCESS",
      statusCode: 200,
      durationMs: 10,
    });

    expect(mockPool.query).not.toHaveBeenCalled();

    // Wait for timer flush
    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(mockPool.query).toHaveBeenCalledTimes(1);
    expect(mockPool.query).toHaveBeenCalledWith(
      expect.stringContaining("INSERT INTO tool_usage_logs"),
      expect.arrayContaining(["req-trace-999"]),
    );

    logger.stop();
  });

  it("should flush all pending logs on flush() (Graceful Shutdown)", async () => {
    const logger = new AuditLogger(mockPool as Pool, {
      batchSize: 100,
      flushIntervalMs: 60_000,
    });

    logger.log({
      requestId: "req-shutdown-1",
      userId: "user-admin",
      toolName: "admin.backup",
      status: "SUCCESS",
      statusCode: 200,
      durationMs: 50,
    });

    expect(mockPool.query).not.toHaveBeenCalled();

    // Graceful shutdown flush
    await logger.flush();

    expect(mockPool.query).toHaveBeenCalledTimes(1);
    expect(mockPool.query).toHaveBeenCalledWith(
      expect.stringContaining("INSERT INTO tool_usage_logs"),
      expect.arrayContaining(["req-shutdown-1"]),
    );

    logger.stop();
  });

  it("should write to local fallback file when DB insert fails", async () => {
    const tmpLogDir = path.join(process.cwd(), "scratch", "test-audit-logs");
    if (fs.existsSync(tmpLogDir)) {
      fs.rmSync(tmpLogDir, { recursive: true, force: true });
    }

    mockPool.query.mockRejectedValueOnce(new Error("Database connection lost"));

    const logger = new AuditLogger(mockPool as Pool, {
      batchSize: 1,
      flushIntervalMs: 10_000,
      fallbackLogDir: tmpLogDir,
    });

    logger.log({
      requestId: "req-db-fail-1",
      userId: "user-fallback",
      toolName: "github.create_issue",
      status: "SUCCESS",
      statusCode: 200,
      durationMs: 45,
      arguments: { title: "DB is down", token: "super-secret" },
    });

    // Wait for async flush
    await new Promise((resolve) => setTimeout(resolve, 20));

    // Verify fallback file was created
    const today = new Date().toISOString().slice(0, 10);
    const expectedFile = path.join(tmpLogDir, `audit-fallback-${today}.jsonl`);
    expect(fs.existsSync(expectedFile)).toBe(true);

    const content = fs.readFileSync(expectedFile, "utf8");
    expect(content).toContain("req-db-fail-1");
    expect(content).toContain("user-fallback");
    expect(content).toContain("github.create_issue");
    // Sensitive argument should be masked even in fallback file
    expect(content).toContain('"token":"********"');
    expect(content).not.toContain("super-secret");

    logger.stop();
    fs.rmSync(tmpLogDir, { recursive: true, force: true });
  });
});
