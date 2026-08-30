import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { ApiKeyService } from "../src/api/apiKeyService.js";

describe("ApiKeyService", () => {
  it("returns the raw key once while storing only its SHA-256 hash", async () => {
    const query = vi.fn()
      .mockResolvedValueOnce({ rows: [{ tool_pattern: "knowledge.*" }] })
      .mockImplementationOnce(async (_sql: string, values: unknown[]) => ({
        rows: [{ id: values[0], name: values[2], key_prefix: values[3], allowed_scopes: ["tool:knowledge.*"] }],
      }));
    const service = new ApiKeyService({ query } as never, { invalidateUser: vi.fn() } as never);

    const result = await service.create("user-1", "codex") as { plainKey: string; apiKey: Record<string, unknown> };

    expect(result.plainKey).toMatch(/^tg_live_[A-Za-z0-9_-]{43}$/);
    const insertValues = query.mock.calls[1]![1] as unknown[];
    expect(insertValues[4]).toBe(createHash("sha256").update(result.plainKey).digest("hex"));
    expect(JSON.stringify(insertValues)).not.toContain(result.plainKey);
    expect(result.apiKey).not.toHaveProperty("key_hash");
  });

  it("soft-revokes only an owned key and invalidates cached principals", async () => {
    const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [{ id: "key-1" }] });
    const invalidateUser = vi.fn();
    const service = new ApiKeyService({ query } as never, { invalidateUser } as never);

    await expect(service.revoke("user-1", "key-1")).resolves.toBe(true);
    expect(query.mock.calls[0]![1]).toEqual(["key-1", "user-1"]);
    expect(invalidateUser).toHaveBeenCalledWith("user-1");
  });
});
