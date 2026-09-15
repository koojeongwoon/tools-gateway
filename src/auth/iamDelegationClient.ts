import type { UpstreamConfig } from "../config/upstreamConfig.js";

type GatewayDelegation = Extract<UpstreamConfig["auth"], { mode: "gateway-delegation" }>;
type Fetch = typeof fetch;

export class IamDelegationError extends Error {
  constructor(readonly status: number) {
    super("IAM delegation token exchange failed");
  }
}

export class IamDelegationClient {
  constructor(
    private readonly iamUrl: string,
    private readonly actorClientId: string,
    private readonly actorClientSecret: string,
    private readonly timeoutMs: number = 5000,
    private readonly fetchImpl: Fetch = fetch,
  ) {}

  async exchange(subjectToken: string, target: GatewayDelegation): Promise<string> {
    const body = new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: subjectToken,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      requested_target_tenant: target.targetTenantId,
      client_id: target.audience,
    });
    if (target.targetOrganizationId) {
      body.set("requested_target_org", target.targetOrganizationId);
    }
    const response = await this.fetchImpl(
      `${this.iamUrl.replace(/\/$/, "")}/api/auth/oauth2/delegation-token`,
      {
        method: "POST",
        headers: {
          accept: "application/json",
          authorization: `Basic ${Buffer.from(`${this.actorClientId}:${this.actorClientSecret}`).toString("base64")}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body,
        signal: AbortSignal.timeout(this.timeoutMs),
      },
    );
    if (!response.ok) throw new IamDelegationError(response.status);
    const payload = await response.json() as Record<string, unknown>;
    if (typeof payload.access_token !== "string" || !payload.access_token) {
      throw new IamDelegationError(502);
    }
    return payload.access_token;
  }
}
