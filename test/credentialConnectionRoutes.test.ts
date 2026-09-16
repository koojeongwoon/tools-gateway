import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import { registerCredentialConnectionRoutes } from "../src/api/credentialConnectionRoutes.js";

const connection = {
  id: "11111111-1111-4111-8111-111111111111",
  owner_type: "USER",
  provider: "OPENAI",
  allowed_actions: ["embedding.create"],
  granted_scopes: [],
  status: "ACTIVE",
  credential_schema: "bearer/v1",
  configuration: {},
  masked_hint: "****alue",
  credential_version: 1,
  expires_at: null,
  revoked_at: null,
  created_at: "2026-09-15T00:00:00Z",
  updated_at: "2026-09-15T00:00:00Z",
};

function testApp(iamAccessToken: string | null = "gateway-user-jwt") {
  const app = Fastify();
  const sessions = {
    resolve: vi.fn().mockResolvedValue({
      subject: "user-1",
      email: "user@example.com",
      ...(iamAccessToken ? { iamAccessToken } : {}),
    }),
  };
  const broker = {
    register: vi.fn().mockResolvedValue(connection),
    list: vi.fn().mockResolvedValue([connection]),
    status: vi.fn().mockResolvedValue(connection),
    rotate: vi.fn().mockResolvedValue({ ...connection, credential_version: 2 }),
    revoke: vi.fn().mockResolvedValue({ ...connection, status: "REVOKED", credential_version: 3 }),
  };
  registerCredentialConnectionRoutes(app, sessions as never, broker as never);
  return { app, broker };
}

describe("credential connection routes", () => {
  it("uses only the server-side IAM token and never adds caller identity", async () => {
    const { app, broker } = testApp();
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/credential-connections",
      headers: { cookie: "tg_session=session-1" },
      payload: {
        owner_type: "USER",
        provider: "OPENAI",
        allowed_actions: ["embedding.create"],
        granted_scopes: [],
        configuration: {},
        credential: {
          schema: "bearer/v1",
          values: { token: "synthetic-secret-value" },
        },
      },
    });

    expect(response.statusCode).toBe(201);
    expect(response.body).not.toContain("synthetic-secret-value");
    expect(broker.register).toHaveBeenCalledWith("gateway-user-jwt", {
      owner_type: "USER",
      provider: "OPENAI",
      allowed_actions: ["embedding.create"],
      granted_scopes: [],
      configuration: {},
      credential: {
        schema: "bearer/v1",
        values: { token: "synthetic-secret-value" },
      },
    });
    expect(JSON.stringify(broker.register.mock.calls[0]?.[1])).not.toContain("user-1");
    await app.close();
  });

  it("does not reflect an invalid credential value", async () => {
    const { app, broker } = testApp();
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/credential-connections",
      headers: { cookie: "tg_session=session-1" },
      payload: {
        owner_type: "USER",
        provider: "OPENAI",
        allowed_actions: ["embedding.create"],
        credential: {
          schema: "bearer/v1",
          values: { "1invalid": "do-not-reflect" },
        },
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.body).not.toContain("do-not-reflect");
    expect(broker.register).not.toHaveBeenCalled();
    await app.close();
  });

  it("rejects the retired scalar secret contract", async () => {
    const { app, broker } = testApp();
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/credential-connections",
      headers: { cookie: "tg_session=session-1" },
      payload: {
        owner_type: "USER",
        provider: "OPENAI",
        allowed_actions: ["embedding.create"],
        secret: "retired-contract",
      },
    });

    expect(response.statusCode).toBe(400);
    expect(response.body).not.toContain("retired-contract");
    expect(broker.register).not.toHaveBeenCalled();
    await app.close();
  });

  it("requires a fresh login when the delegated IAM token expired", async () => {
    const { app, broker } = testApp(null);
    const response = await app.inject({
      method: "GET",
      url: "/api/v1/credential-connections?owner_type=USER",
      headers: { cookie: "tg_session=session-1" },
    });

    expect(response.statusCode).toBe(401);
    expect(broker.list).not.toHaveBeenCalled();
    await app.close();
  });
});
