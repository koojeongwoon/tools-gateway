import Fastify from "fastify";
import { describe, expect, it, vi } from "vitest";
import { registerAiCredentialRoutes } from "../src/api/aiCredentialRoutes.js";

const sessionWithToken = {
  subject: "iam-user-1",
  email: "user@example.com",
  iamAccessToken: "delegated-user-jwt",
};

function registerTestAiCredentialRoutes(options?: { session?: typeof sessionWithToken | undefined }) {
  const app = Fastify();
  const sessions = {
    resolve: vi.fn().mockResolvedValue(options?.session ?? sessionWithToken),
    beginLogin: vi.fn(),
    completeLogin: vi.fn(),
    revoke: vi.fn(),
    getSignoutUrl: vi.fn(),
  };
  const iamClient = {
    getCredentialStatus: vi.fn().mockResolvedValue({
      codex: { linked: true },
      openai_api_key: { configured: true, masked_hint: "sk-***1234" },
      embedding_api_key: { configured: false },
    }),
    startCodexDeviceFlow: vi.fn().mockResolvedValue({ device_auth_id: "device-1" }),
    checkCodexDeviceFlow: vi.fn().mockResolvedValue({ status: "completed" }),
    saveApiKey: vi.fn().mockResolvedValue({ configured: true }),
    deleteApiKey: vi.fn().mockResolvedValue(true),
  };

  registerAiCredentialRoutes(app, {
    sessions: sessions as never,
    iamAiClient: iamClient as never,
    iamTenantId: "tenant-1",
  });

  return { app, iamClient };
}

describe("management AI credential routes", () => {
  it("returns only tenant credential status to the dashboard", async () => {
    const { app, iamClient } = registerTestAiCredentialRoutes();

    const response = await app.inject({
      method: "GET",
      url: "/api/v1/ai-credentials/bundle",
      headers: { cookie: "tg_session=session-1" },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      codex: { linked: true },
      openai_api_key: { configured: true, masked_hint: "sk-***1234" },
      embedding_api_key: { configured: false },
    });
    expect(iamClient.getCredentialStatus).toHaveBeenCalledWith("tenant-1");
    await app.close();
  });

  it("uses the session's delegated IAM JWT for device start and completion", async () => {
    const { app, iamClient } = registerTestAiCredentialRoutes();

    const start = await app.inject({
      method: "POST",
      url: "/api/v1/ai-credentials/codex/device/start",
      headers: { cookie: "tg_session=session-1" },
    });
    const check = await app.inject({
      method: "POST",
      url: "/api/v1/ai-credentials/codex/device/check",
      headers: { cookie: "tg_session=session-1" },
      payload: { deviceAuthId: "device-1", userCode: "ABCD-1234" },
    });

    expect(start.statusCode).toBe(200);
    expect(check.statusCode).toBe(200);
    expect(iamClient.startCodexDeviceFlow).toHaveBeenCalledWith("delegated-user-jwt");
    expect(iamClient.checkCodexDeviceFlow).toHaveBeenCalledWith(
      "delegated-user-jwt",
      "device-1",
      "ABCD-1234",
    );
    await app.close();
  });

  it("requires a fresh IAM login when the opaque session has no usable delegated token", async () => {
    const { app, iamClient } = registerTestAiCredentialRoutes({
      session: { subject: "iam-user-1", email: "user@example.com" } as typeof sessionWithToken,
    });

    const response = await app.inject({
      method: "POST",
      url: "/api/v1/ai-credentials/codex/device/start",
      headers: { cookie: "tg_session=session-1" },
    });

    expect(response.statusCode).toBe(401);
    expect(iamClient.startCodexDeviceFlow).not.toHaveBeenCalled();
    await app.close();
  });

  it("forwards AI key mutations with the delegated JWT and no user identity fields", async () => {
    const { app, iamClient } = registerTestAiCredentialRoutes();

    const saved = await app.inject({
      method: "POST",
      url: "/api/v1/ai-credentials/keys",
      headers: { cookie: "tg_session=session-1" },
      payload: { provider: "OPENAI_API_KEY", apiKey: "sk-test" },
    });
    const deleted = await app.inject({
      method: "DELETE",
      url: "/api/v1/ai-credentials/keys/OPENAI_API_KEY",
      headers: { cookie: "tg_session=session-1" },
    });

    expect(saved.statusCode).toBe(200);
    expect(deleted.statusCode).toBe(204);
    expect(iamClient.saveApiKey).toHaveBeenCalledWith(
      "delegated-user-jwt",
      "OPENAI_API_KEY",
      "sk-test",
    );
    expect(iamClient.deleteApiKey).toHaveBeenCalledWith(
      "delegated-user-jwt",
      "OPENAI_API_KEY",
    );
    await app.close();
  });
});
