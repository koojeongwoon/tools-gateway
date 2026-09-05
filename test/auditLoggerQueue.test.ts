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
});
