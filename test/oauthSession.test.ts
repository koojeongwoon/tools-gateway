import type { RedisClientType } from "redis";
import { describe, expect, it, vi } from "vitest";
import { loadOAuthConfig, OAuthSessionStore } from "../src/auth/oauthSession.js";

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
      TOOLS_GATEWAY_CLIENT_ID: "cli_ab3d5bb39f894dff",
      TOOLS_GATEWAY_CLIENT_SECRET: "secret",
    });
    expect(config?.redirectUri).toBe("https://tools-gateway.lynply.com/api/v1/auth/sso-callback");
    expect(config?.tenantId).toBe("ten_9664c024babc4110");
    expect(config?.issuer).toBe("https://auth.snappytory.com/t/ten_9664c024babc4110");
    expect(config?.authorizationEndpoint).toBe("https://auth.snappytory.com/t/ten_9664c024babc4110/oauth2/authorize");
    expect(config?.tokenEndpoint).toBe("https://auth.snappytory.com/t/ten_9664c024babc4110/oauth2/token");
    expect(config?.jwksUri).toBe("https://auth.snappytory.com/t/ten_9664c024babc4110/oauth2/jwks");
    expect(config?.signoutUrl).toBe("https://auth.snappytory.com/portal/tenants/ten_9664c024babc4110/signout?clientId=cli_ab3d5bb39f894dff");
    expect(config?.clientSecret).toBe("secret");
  });

  it("rejects an issuer outside the configured tenant boundary", () => {
    expect(() => loadOAuthConfig({
      SSO_ENABLED: "true",
      TOOLS_GATEWAY_CLIENT_ID: "cli_ab3d5bb39f894dff",
      TOOLS_GATEWAY_CLIENT_SECRET: "secret",
      AUTH_TOKEN_ISSUER: "https://auth.snappytory.com",
    })).toThrow("AUTH_TOKEN_ISSUER");
  });

  it("starts authorization from the tenant endpoint without a legacy tenant parameter", async () => {
    const config = loadOAuthConfig({
      SSO_ENABLED: "true",
      TOOLS_GATEWAY_CLIENT_ID: "cli_ab3d5bb39f894dff",
      TOOLS_GATEWAY_CLIENT_SECRET: "secret",
    });
    const redis = { set: vi.fn().mockResolvedValue("OK") } as unknown as RedisClientType;
    const sessionStore = new OAuthSessionStore(redis, config!);

    const { authorizationUrl } = await sessionStore.beginLogin();
    const url = new URL(authorizationUrl);
    expect(url.origin + url.pathname).toBe(config?.authorizationEndpoint);
    expect(url.searchParams.get("client_id")).toBe("cli_ab3d5bb39f894dff");
    expect(url.searchParams.has("tenant")).toBe(false);
  });

  it("makes a delegated IAM access token available only while it is unexpired", async () => {
    const config = loadOAuthConfig({
      SSO_ENABLED: "true",
      TOOLS_GATEWAY_CLIENT_ID: "tools-gateway",
      TOOLS_GATEWAY_CLIENT_SECRET: "secret",
    });
    const redis = {
      get: vi.fn().mockResolvedValue(JSON.stringify({
        subject: "iam-user-1",
        iamAccessToken: "delegated-user-jwt",
        iamAccessTokenExpiresAt: Math.floor(Date.now() / 1000) + 60,
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      })),
    } as unknown as RedisClientType;
    const sessionStore = new OAuthSessionStore(redis, config!);

    await expect(sessionStore.resolve("opaque-session")).resolves.toEqual({
      subject: "iam-user-1",
      iamAccessToken: "delegated-user-jwt",
    });
  });
});
