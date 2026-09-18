import { describe, expect, it, vi } from "vitest";
import { applyUserSyncEvent } from "../src/events/userSyncConsumer.js";

describe("legacy user sync compatibility", () => {
  it("does not pre-register a local user for USER_CREATED", async () => {
    const client = {
      query: vi.fn().mockResolvedValue({ rows: [] }),
      release: vi.fn(),
    };
    const pool = { connect: vi.fn().mockResolvedValue(client) };
    const verifier = { invalidateUser: vi.fn() };

    await applyUserSyncEvent(pool as never, verifier as never, {
      schema: "auth.user.v1",
      eventId: "evt-1",
      eventType: "USER_CREATED",
      occurredAt: "2026-09-18T00:00:00Z",
      subject: { id: "iam-user-1", email: "user@example.com", name: "User" },
    });

    expect(client.query.mock.calls.map(([sql]) => sql)).toEqual(["BEGIN", "COMMIT"]);
    expect(verifier.invalidateUser).not.toHaveBeenCalled();
  });
});
