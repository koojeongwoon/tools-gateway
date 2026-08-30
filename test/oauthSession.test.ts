import { describe, expect, it } from "vitest";
import { loadOAuthConfig } from "../src/auth/oauthSession.js";

describe("OAuth configuration", () => {
  it("is disabled unless explicitly enabled", () => {
    expect(loadOAuthConfig({})).toBeUndefined();
  });

  it("fails closed when the OAuth client secret is absent", () => {
    expect(() => loadOAuthConfig({ SSO_ENABLED: "true", TOOLS_GATEWAY_CLIENT_ID: "tools-gateway" }))
      .toThrow("TOOLS_GATEWAY_CLIENT_SECRET");
  });

  it("uses the registered production callback contract", () => {
    const config = loadOAuthConfig({
      SSO_ENABLED: "true",
      TOOLS_GATEWAY_CLIENT_ID: "tools-gateway",
      TOOLS_GATEWAY_CLIENT_SECRET: "secret",
    });
    expect(config?.redirectUri).toBe("https://tools-gateway.lynply.com/api/v1/auth/sso-callback");
    expect(config?.tenantId).toBe("tools-gateway");
    expect(config?.clientSecret).toBe("secret");
  });
});
