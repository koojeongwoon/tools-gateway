import { describe, expect, it, vi } from "vitest";
import { applyUserServiceAccessEvent } from "../src/events/userServiceAccessConsumer.js";
import { parseUserServiceAccessEvent } from "../src/events/userServiceAccessEvent.js";

const expected = {
  issuer: "https://auth.example/t/tenant-a",
  tenantId: "tenant-a",
  clientId: "tools-gateway-service",
};

function event(eventType: "USER_SERVICE_ENABLED" | "USER_SERVICE_DISABLED", accessVersion = 1, clientId = expected.clientId) {
  const status = eventType === "USER_SERVICE_ENABLED" ? "ACTIVE" : "DISABLED";
  return parseUserServiceAccessEvent({
    schema: "iam.user-service-access.v1",
    eventId: `evt-access-${eventType}-${accessVersion}`,
    eventType,
    occurredAt: "2026-09-18T00:00:00Z",
    issuer: expected.issuer,
    tenantId: expected.tenantId,
    subjectId: "iam-user-1",
    clientId,
    accessVersion,
    status,
  });
}

describe("canonical user service access application", () => {
  it("ignores event for different client ID without database write", async () => {
    const client = {
      query: vi.fn(),
      release: vi.fn(),
    };
    const verifier = { invalidateUser: vi.fn() };

    const result = await applyUserServiceAccessEvent(
      { connect: vi.fn().mockResolvedValue(client) } as never,
      verifier as never,
      event("USER_SERVICE_ENABLED", 1, "other-service"),
      expected,
    );

    expect(result).toBe(false);
    expect(client.query).not.toHaveBeenCalled();
  });

  it("applies USER_SERVICE_ENABLED event for matching client", async () => {
    const client = {
      query: vi.fn()
        .mockResolvedValueOnce({}) // BEGIN
        .mockResolvedValueOnce({ rowCount: 1 }) // INSERT events
        .mockResolvedValueOnce({ rowCount: 1 }) // INSERT states
        .mockResolvedValueOnce({}), // COMMIT
      release: vi.fn(),
    };
    const verifier = { invalidateUser: vi.fn() };

    await expect(applyUserServiceAccessEvent(
      { connect: vi.fn().mockResolvedValue(client) } as never,
      verifier as never,
      event("USER_SERVICE_ENABLED", 1),
      expected,
    )).resolves.toBe(true);

    expect(client.query).toHaveBeenCalledWith("COMMIT");
  });

  it("applies USER_SERVICE_DISABLED event, revokes API keys and invalidates cache and sessions", async () => {
    const client = {
      query: vi.fn()
        .mockResolvedValueOnce({}) // BEGIN
        .mockResolvedValueOnce({ rowCount: 1 }) // INSERT events
        .mockResolvedValueOnce({ rowCount: 1 }) // INSERT states
        .mockResolvedValueOnce({ rowCount: 1, rows: [{ id: "tg-user-1" }] }) // SELECT user
        .mockResolvedValueOnce({ rowCount: 1 }) // UPDATE api_keys
        .mockResolvedValueOnce({}), // COMMIT
      release: vi.fn(),
    };
    const verifier = { invalidateUser: vi.fn() };
    const invalidateSessions = vi.fn().mockResolvedValue(undefined);

    const result = await applyUserServiceAccessEvent(
      { connect: vi.fn().mockResolvedValue(client) } as never,
      verifier as never,
      event("USER_SERVICE_DISABLED", 2),
      expected,
      invalidateSessions,
    );

    expect(result).toBe(true);
    expect(verifier.invalidateUser).toHaveBeenCalledWith("tg-user-1");
    expect(invalidateSessions).toHaveBeenCalledWith("iam-user-1");
    expect(client.query).toHaveBeenCalledWith("COMMIT");
  });
});
