import { describe, expect, it } from "vitest";
import {
  OutboundSecretLeakGuard,
  SecretEgressBlockedError,
} from "../src/policy/outboundSecretLeakGuard.js";

describe("OutboundSecretLeakGuard", () => {
  const guard = new OutboundSecretLeakGuard();

  it("blocks sensitive argument names before an upstream call", () => {
    expect(() => guard.validate({ credentials: { apiKey: "not-a-real-key" } }))
      .toThrow(SecretEgressBlockedError);
  });

  it("blocks high-entropy strings even in otherwise benign argument names", () => {
    const syntheticProbe = "p2Y9aK7qL3vX8nR4mT6cW1fH5sD0jB9uE2gI7oN";

    expect(() => guard.validate({ query: `find ${syntheticProbe}` }))
      .toThrow(SecretEgressBlockedError);
  });

  it("permits ordinary tool arguments", () => {
    expect(() => guard.validate({ repository: "tools-gateway", path: "README.md" }))
      .not.toThrow();
  });
});
