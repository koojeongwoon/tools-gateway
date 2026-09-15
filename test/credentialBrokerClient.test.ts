import { describe, expect, it, vi } from "vitest";
import { CredentialBrokerClient } from "../src/credential/credentialBrokerClient.js";

const connection = {
  id: "11111111-1111-4111-8111-111111111111",
  owner_type: "USER" as const,
  provider: "OPENAI",
  allowed_actions: ["embedding.create"],
  granted_scopes: [],
  status: "ACTIVE" as const,
  masked_hint: "****alue",
  credential_version: 1,
  expires_at: null,
  revoked_at: null,
  created_at: "2026-09-15T00:00:00Z",
  updated_at: "2026-09-15T00:00:00Z",
};

describe("CredentialBrokerClient", () => {
  it("exchanges the user token and presents a separate workload token", async () => {
    const fetchImpl = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ access_token: "broker-user-jwt" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ success: true, data: connection }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }));
    const client = new CredentialBrokerClient(
      "http://credential-broker.vault.svc.cluster.local:8000",
      "https://auth.snappytory.com",
      "tenant-1",
      "credential-broker",
      "org-1",
      "/unused",
      5000,
      fetchImpl,
      async () => "workload-jwt",
    );

    const result = await client.register("gateway-user-jwt", {
      owner_type: "USER",
      provider: "OPENAI",
      allowed_actions: ["embedding.create"],
      granted_scopes: [],
      secret: "synthetic-secret-value",
    });

    expect(result).toEqual(connection);
    const exchange = fetchImpl.mock.calls[0];
    expect(exchange?.[0]).toBe("https://auth.snappytory.com/api/auth/oauth2/token");
    const exchangeBody = String(exchange?.[1]?.body);
    expect(exchangeBody).toContain("subject_token=gateway-user-jwt");
    expect(exchangeBody).toContain("client_id=credential-broker");
    expect(exchangeBody).toContain("requested_target_org=org-1");
    expect(exchangeBody).not.toContain("synthetic-secret-value");

    const brokerCall = fetchImpl.mock.calls[1];
    expect(brokerCall?.[1]?.headers).toMatchObject({
      authorization: "Bearer broker-user-jwt",
      "x-workload-authorization": "Bearer workload-jwt",
    });
    expect(String(brokerCall?.[1]?.body)).toContain("synthetic-secret-value");
    expect(JSON.stringify(result)).not.toContain("synthetic-secret-value");
  });
});
