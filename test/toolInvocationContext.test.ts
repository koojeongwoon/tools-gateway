import { describe, expect, it, vi } from "vitest";
import { ToolInvocationContext } from "../src/domain/toolInvocationContext.js";
import { AuditLogger } from "../src/audit/auditLogger.js";

describe("ToolInvocationContext (Domain Context)", () => {
  it("executes operation and logs SUCCESS audit metrics", async () => {
    const mockPool = { query: vi.fn().mockResolvedValue({ rowCount: 1 }) };
    const auditLogger = new AuditLogger(mockPool as any);
    const logSpy = vi.spyOn(auditLogger, "log");

    const context = new ToolInvocationContext({
      requestContext: {
        userId: "user-test",
        apiKeyId: "key-test",
        ipAddress: "127.0.0.1",
        userAgent: "vitest-agent",
      },
      auditLogger,
    });

    const mockOp = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "hello" }] });
    const result = await context.invoke("github.get_file", { path: "a.txt" }, mockOp);

    expect(result).toEqual({ content: [{ type: "text", text: "hello" }] });
    expect(logSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: "user-test",
        apiKeyId: "key-test",
        toolName: "github.get_file",
        status: "SUCCESS",
        statusCode: 200,
      }),
    );
    auditLogger.stop();
  });

  it("handles error in operation, logs ERROR audit entry and rethrows error", async () => {
    const mockPool = { query: vi.fn().mockResolvedValue({ rowCount: 1 }) };
    const auditLogger = new AuditLogger(mockPool as any);
    const logSpy = vi.spyOn(auditLogger, "log");

    const context = new ToolInvocationContext({
      requestContext: { userId: "user-test" },
      auditLogger,
    });

    const mockOp = vi.fn().mockRejectedValue(new Error("upstream timeout"));

    await expect(
      context.invoke("github.get_file", {}, mockOp),
    ).rejects.toThrow("upstream timeout");

    expect(logSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: "user-test",
        toolName: "github.get_file",
        status: "ERROR",
        statusCode: 500,
      }),
    );
    auditLogger.stop();
  });
});
