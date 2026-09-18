import { describe, expect, it } from "vitest";
import { parseUserServiceAccessEvent } from "../src/events/userServiceAccessEvent.js";

const baseEvent = {
  schema: "iam.user-service-access.v1",
  eventId: "019d09c4-64f0-7000-8000-000000000010",
  eventType: "USER_SERVICE_ENABLED",
  occurredAt: "2026-09-18T00:00:00Z",
  issuer: "https://auth.snappytory.com/t/ten_9664c024babc4110",
  tenantId: "ten_9664c024babc4110",
  subjectId: "usr_contract_fixture",
  clientId: "tools-gateway-service",
  accessVersion: 1,
  status: "ACTIVE",
} as const;

describe("IAM user service access contract", () => {
  it("parses canonical service access events", () => {
    expect(parseUserServiceAccessEvent(baseEvent)).toEqual(baseEvent);

    const disabled = {
      ...baseEvent,
      eventType: "USER_SERVICE_DISABLED" as const,
      status: "DISABLED" as const,
      accessVersion: 2,
    };
    expect(parseUserServiceAccessEvent(disabled)).toEqual(disabled);

    const withdrawn = {
      ...baseEvent,
      eventType: "USER_SERVICE_WITHDRAWN" as const,
      status: "WITHDRAWN" as const,
      accessVersion: 3,
    };
    expect(parseUserServiceAccessEvent(withdrawn)).toEqual(withdrawn);
  });

  it("rejects status and eventType mismatch", () => {
    expect(() => parseUserServiceAccessEvent({
      ...baseEvent,
      status: "DISABLED",
    })).toThrow();
  });

  it("rejects invalid schema or extra fields", () => {
    expect(() => parseUserServiceAccessEvent({
      ...baseEvent,
      schema: "iam.user.v1",
    })).toThrow();

    expect(() => parseUserServiceAccessEvent({
      ...baseEvent,
      extraField: "unexpected",
    })).toThrow();
  });
});
