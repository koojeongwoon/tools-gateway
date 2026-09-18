import { describe, expect, it, vi } from "vitest";
import { applyUserLifecycleEvent } from "../src/events/userLifecycleConsumer.js";
import { parseUserLifecycleEvent } from "../src/events/userLifecycleEvent.js";

const expected = { issuer: "https://auth.example/t/tenant-a", tenantId: "tenant-a" };

function event(eventType: "USER_CREATED" | "USER_DISABLED", userVersion = 1) {
  return parseUserLifecycleEvent({
    schema: "iam.user.v1",
    eventId: `evt-${eventType}-${userVersion}`,
    eventType,
    occurredAt: "2026-09-18T00:00:00Z",
    issuer: expected.issuer,
    tenantId: expected.tenantId,
    subjectId: "iam-user-1",
    userVersion,
    ...(eventType === "USER_CREATED" ? { profile: { email: "user@example.com", name: "User" } } : {}),
  });
}

describe("canonical user lifecycle application", () => {
  it("records USER_CREATED state without creating a local user", async () => {
    const client = {
      query: vi.fn()
        .mockResolvedValueOnce({})
        .mockResolvedValueOnce({ rowCount: 1 })
        .mockResolvedValueOnce({ rowCount: 1 })
        .mockResolvedValueOnce({}),
      release: vi.fn(),
    };
    const verifier = { invalidateUser: vi.fn() };

    await expect(applyUserLifecycleEvent(
      { connect: vi.fn().mockResolvedValue(client) } as never,
      verifier as never, event("USER_CREATED"), expected,
    )).resolves.toBe(true);

    expect(client.query.mock.calls.some(([sql]) => String(sql).includes("UPDATE users"))).toBe(false);
  });

  it("blocks an existing user and invalidates keys and sessions after commit", async () => {
    const client = {
      query: vi.fn()
        .mockResolvedValueOnce({})
        .mockResolvedValueOnce({ rowCount: 1 })
        .mockResolvedValueOnce({ rowCount: 1 })
        .mockResolvedValueOnce({ rowCount: 1, rows: [{ id: "tg-user-1" }] })
        .mockResolvedValueOnce({})
        .mockResolvedValueOnce({}),
      release: vi.fn(),
    };
    const verifier = { invalidateUser: vi.fn() };
    const invalidateSessions = vi.fn();

    await applyUserLifecycleEvent(
      { connect: vi.fn().mockResolvedValue(client) } as never,
      verifier as never, event("USER_DISABLED", 2), expected, invalidateSessions,
    );

    expect(verifier.invalidateUser).toHaveBeenCalledWith("tg-user-1");
    expect(invalidateSessions).toHaveBeenCalledWith("iam-user-1");
    expect(client.query).toHaveBeenCalledWith("COMMIT");
  });
});
