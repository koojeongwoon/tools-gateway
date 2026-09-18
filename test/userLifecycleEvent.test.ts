import { describe, expect, it } from "vitest";
import { parseUserLifecycleEvent } from "../src/events/userLifecycleEvent.js";

const disabledEvent = {
  schema: "iam.user.v1",
  eventId: "019d09c4-64f0-7000-8000-000000000001",
  eventType: "USER_DISABLED",
  occurredAt: "2026-09-18T00:00:00Z",
  issuer: "https://auth.snappytory.com/t/ten_9664c024babc4110",
  tenantId: "ten_9664c024babc4110",
  subjectId: "usr_contract_fixture",
  userVersion: 2,
} as const;

describe("IAM user lifecycle contract", () => {
  it("parses the canonical disabled event", () => {
    expect(parseUserLifecycleEvent(disabledEvent)).toEqual(disabledEvent);
  });

  it("rejects a profile on a status event", () => {
    expect(() => parseUserLifecycleEvent({
      ...disabledEvent,
      profile: { email: "u@example.com", name: "U" },
    })).toThrow();
  });
});
