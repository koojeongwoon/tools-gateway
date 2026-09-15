import { readFile } from "node:fs/promises";

export type CredentialOwnerType = "USER" | "TENANT";

export interface CredentialConnection {
  id: string;
  owner_type: CredentialOwnerType;
  provider: string;
  allowed_actions: string[];
  granted_scopes: string[];
  status: "ACTIVE" | "EXPIRED" | "REVOKED";
  masked_hint?: string | null;
  credential_version: number;
  expires_at?: string | null | undefined;
  revoked_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface RegisterCredentialConnection {
  owner_type: CredentialOwnerType;
  provider: string;
  allowed_actions: string[];
  granted_scopes: string[];
  secret: string;
  expires_at?: string | null | undefined;
}

export interface RotateCredentialConnection {
  owner_type: CredentialOwnerType;
  secret: string;
  expires_at?: string | null | undefined;
}

interface BrokerEnvelope<T> {
  success: boolean;
  data: T | null;
  error?: { code?: string } | null;
}

type Fetch = typeof fetch;

export class CredentialBrokerError extends Error {
  constructor(
    readonly status: number,
    readonly code: string = "CREDENTIAL_BROKER_REQUEST_FAILED",
  ) {
    super("Credential Broker request failed");
  }
}

export class CredentialBrokerClient {
  constructor(
    private readonly brokerUrl: string,
    private readonly iamUrl: string,
    private readonly tenantId: string,
    private readonly brokerClientId: string,
    private readonly targetOrgId: string | undefined,
    private readonly workloadTokenFile: string,
    private readonly timeoutMs: number = 5000,
    private readonly fetchImpl: Fetch = fetch,
    private readonly workloadTokenProvider: () => Promise<string> = async () =>
      (await readFile(this.workloadTokenFile, "utf8")).trim(),
  ) {}

  async register(
    userToken: string,
    connection: RegisterCredentialConnection,
  ): Promise<CredentialConnection> {
    return this.request(userToken, "/v1/connections", "POST", connection);
  }

  async list(userToken: string, ownerType: CredentialOwnerType): Promise<CredentialConnection[]> {
    return this.request(
      userToken,
      `/v1/connections?${new URLSearchParams({ owner_type: ownerType })}`,
      "GET",
    );
  }

  async status(
    userToken: string,
    connectionId: string,
    ownerType: CredentialOwnerType,
  ): Promise<CredentialConnection> {
    return this.request(
      userToken,
      `/v1/connections/${encodeURIComponent(connectionId)}?${new URLSearchParams({ owner_type: ownerType })}`,
      "GET",
    );
  }

  async rotate(
    userToken: string,
    connectionId: string,
    connection: RotateCredentialConnection,
  ): Promise<CredentialConnection> {
    return this.request(
      userToken,
      `/v1/connections/${encodeURIComponent(connectionId)}/rotate`,
      "POST",
      connection,
    );
  }

  async revoke(
    userToken: string,
    connectionId: string,
    ownerType: CredentialOwnerType,
  ): Promise<CredentialConnection> {
    return this.request(
      userToken,
      `/v1/connections/${encodeURIComponent(connectionId)}/revoke?${new URLSearchParams({ owner_type: ownerType })}`,
      "POST",
    );
  }

  private async exchangeUserToken(subjectToken: string): Promise<string> {
    const request = new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
      subject_token: subjectToken,
      subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
      requested_target_tenant: this.tenantId,
      client_id: this.brokerClientId,
    });
    if (this.targetOrgId) request.set("requested_target_org", this.targetOrgId);

    const response = await this.fetchImpl(`${this.iamUrl.replace(/\/$/, "")}/api/auth/oauth2/token`, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/x-www-form-urlencoded",
      },
      body: request,
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) throw new CredentialBrokerError(response.status, "IAM_TOKEN_EXCHANGE_FAILED");
    const payload = await response.json() as Record<string, unknown>;
    if (typeof payload.access_token !== "string" || !payload.access_token) {
      throw new CredentialBrokerError(502, "IAM_TOKEN_EXCHANGE_FAILED");
    }
    return payload.access_token;
  }

  private async request<T>(
    subjectToken: string,
    path: string,
    method: "GET" | "POST",
    body?: unknown,
  ): Promise<T> {
    const [brokerToken, workloadToken] = await Promise.all([
      this.exchangeUserToken(subjectToken),
      this.workloadTokenProvider(),
    ]);
    if (!workloadToken) throw new CredentialBrokerError(503, "WORKLOAD_TOKEN_UNAVAILABLE");

    const response = await this.fetchImpl(`${this.brokerUrl.replace(/\/$/, "")}${path}`, {
      method,
      headers: {
        accept: "application/json",
        authorization: `Bearer ${brokerToken}`,
        "x-workload-authorization": `Bearer ${workloadToken}`,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const envelope = await response.json().catch(() => undefined) as BrokerEnvelope<T> | undefined;
    if (!response.ok || !envelope?.success || envelope.data === null) {
      throw new CredentialBrokerError(
        response.status,
        envelope?.error?.code ?? "CREDENTIAL_BROKER_REQUEST_FAILED",
      );
    }
    return envelope.data;
  }
}
