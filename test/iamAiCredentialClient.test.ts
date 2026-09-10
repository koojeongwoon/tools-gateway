import { afterEach, describe, expect, it, vi } from "vitest";
import { IamAiCredentialClient } from "../src/credential/iamAiCredentialClient.js";

describe("IamAiCredentialClient contract", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("uses the tenant-scoped Basic-auth bundle contract and exposes only status", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      codex: { linked: true, access_token: "raw-codex-token", source: "USER" },
      openai_api_key: { configured: true, api_key: "raw-openai-key", masked_hint: "sk-***1234" },
      embedding_api_key: { configured: false },
    })));
    vi.stubGlobal("fetch", fetchMock);
    const client = new IamAiCredentialClient("https://iam.example", 5000, "gateway", "secret");

    await expect(client.getCredentialStatus("tenant-1")).resolves.toEqual({
      codex: { linked: true, source: "USER" },
      openai_api_key: { configured: true, masked_hint: "sk-***1234" },
      embedding_api_key: { configured: false },
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "https://iam.example/api/v1/credentials/ai-bundle?tenant_id=tenant-1",
      expect.objectContaining({
        headers: { Authorization: "Basic Z2F0ZXdheTpzZWNyZXQ=" },
      }),
    );
  });

  it("uses the delegated IAM user JWT for device flow without sending a user id", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ device_auth_id: "device-1" })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ status: "completed" })));
    vi.stubGlobal("fetch", fetchMock);
    const client = new IamAiCredentialClient("https://iam.example");

    await client.startCodexDeviceFlow("user-jwt");
    await client.checkCodexDeviceFlow("user-jwt", "device-1", "ABCD-1234");

    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      headers: { Authorization: "Bearer user-jwt" },
    });
    expect(fetchMock.mock.calls[1]?.[1]).toMatchObject({
      headers: {
        Authorization: "Bearer user-jwt",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ deviceAuthId: "device-1", userCode: "ABCD-1234" }),
    });
  });

  it("uses a delegated IAM JWT and tenant-derived body for shared AI API keys", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ configured: true })))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);
    const client = new IamAiCredentialClient("https://iam.example", 5000, "gateway", "secret");

    await client.saveApiKey("user-jwt", "OPENAI_API_KEY", "sk-test");
    await client.deleteApiKey("user-jwt", "OPENAI_API_KEY");

    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({
      method: "POST",
      headers: {
        Authorization: "Bearer user-jwt",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ provider: "OPENAI_API_KEY", apiKey: "sk-test" }),
    });
    expect(fetchMock.mock.calls[1]?.[1]).toMatchObject({
      method: "DELETE",
      headers: {
        Authorization: "Bearer user-jwt",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ provider: "OPENAI_API_KEY" }),
    });
  });
});
