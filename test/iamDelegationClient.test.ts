import { describe, expect, it, vi } from "vitest";
import { IamDelegationClient } from "../src/auth/iamDelegationClient.js";

describe("IamDelegationClient", () => {
  it("authenticates the gateway and exchanges the user token for one audience", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: "knowledge-delegation-jwt",
      token_type: "Bearer",
      expires_in: 300,
    }), { status: 200, headers: { "content-type": "application/json" } }));
    const client = new IamDelegationClient(
      "https://auth.example", "tools-gateway", "actor-secret", 5000, fetchImpl,
    );

    await expect(client.exchange("gateway-user-jwt", {
      mode: "gateway-delegation",
      audience: "knowledge-service",
      targetTenantId: "tenant-1",
      targetOrganizationId: "org-1",
    })).resolves.toBe("knowledge-delegation-jwt");

    const [url, request] = fetchImpl.mock.calls[0]!;
    expect(url).toBe("https://auth.example/api/auth/oauth2/delegation-token");
    expect(request.headers.authorization).toBe(`Basic ${Buffer.from("tools-gateway:actor-secret").toString("base64")}`);
    expect(String(request.body)).toContain("subject_token=gateway-user-jwt");
    expect(String(request.body)).toContain("client_id=knowledge-service");
    expect(String(request.body)).toContain("requested_target_org=org-1");
    expect(String(url)).not.toContain("gateway-user-jwt");
  });
});
