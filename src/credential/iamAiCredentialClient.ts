/**
 * IAM 중앙 인증 서버의 테넌트 공용 AI 자격증명과 Codex Device Flow를 호출하는 클라이언트.
 */

interface ServiceAiBundle {
  tenant_id?: string;
  codex?: {
    linked: boolean;
    access_token?: string;
    token_type?: string;
    expires_in?: number;
    source?: string;
  };
  openai_api_key?: {
    configured: boolean;
    api_key?: string;
    masked_hint?: string;
    source?: string;
  };
  embedding_api_key?: {
    configured: boolean;
    api_key?: string;
    masked_hint?: string;
    source?: string;
  };
}

export interface AiCredentialStatus {
  codex: { linked: boolean; source?: string };
  openai_api_key: { configured: boolean; masked_hint?: string; source?: string };
  embedding_api_key: { configured: boolean; masked_hint?: string; source?: string };
}

export interface DeviceAuthInitResponse {
  device_code: string;
  device_auth_id: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
}

export class IamAiCredentialClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly clientId: string | undefined;
  private readonly clientSecret: string | undefined;

  constructor(
    baseUrl?: string,
    timeoutMs: number = 5000,
    clientId?: string,
    clientSecret?: string
  ) {
    this.baseUrl = (baseUrl || process.env.IAM_SERVER_URL || "http://localhost:8080").replace(/\/$/, "");
    this.timeoutMs = timeoutMs;
    this.clientId = clientId ?? process.env.TOOLS_GATEWAY_CLIENT_ID ?? undefined;
    this.clientSecret = clientSecret ?? process.env.TOOLS_GATEWAY_CLIENT_SECRET ?? undefined;
  }

  private getAuthHeaders(): Record<string, string> {
    if (this.clientId && this.clientSecret) {
      const basic = Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");
      return { Authorization: `Basic ${basic}` };
    }
    return {};
  }

  /**
   * IAM service contract: a registered service may obtain a tenant-scoped
   * bundle with its client credentials. Callers must not forward this raw
   * bundle to a browser.
   */
  async getServiceAiBundle(tenantId: string): Promise<ServiceAiBundle | null> {
    const query = new URLSearchParams({ tenant_id: tenantId });
    const url = `${this.baseUrl}/api/v1/credentials/ai-bundle?${query}`;

    try {
      const response = await fetch(url, {
        method: "GET",
        headers: {
          ...this.getAuthHeaders(),
        },
        signal: AbortSignal.timeout(this.timeoutMs),
      });

      if (!response.ok) {
        return null;
      }

      return (await response.json()) as ServiceAiBundle;
    } catch (err) {
      console.warn(`[IamAiCredentialClient] Failed to fetch AI bundle from ${this.baseUrl}:`, err);
      return null;
    }
  }

  async getCredentialStatus(tenantId: string): Promise<AiCredentialStatus | null> {
    const bundle = await this.getServiceAiBundle(tenantId);
    if (!bundle) return null;
    return {
      codex: {
        linked: bundle.codex?.linked === true,
        ...(bundle.codex?.source ? { source: bundle.codex.source } : {}),
      },
      openai_api_key: {
        configured: bundle.openai_api_key?.configured === true,
        ...(bundle.openai_api_key?.masked_hint
          ? { masked_hint: bundle.openai_api_key.masked_hint }
          : {}),
        ...(bundle.openai_api_key?.source ? { source: bundle.openai_api_key.source } : {}),
      },
      embedding_api_key: {
        configured: bundle.embedding_api_key?.configured === true,
        ...(bundle.embedding_api_key?.masked_hint
          ? { masked_hint: bundle.embedding_api_key.masked_hint }
          : {}),
        ...(bundle.embedding_api_key?.source ? { source: bundle.embedding_api_key.source } : {}),
      },
    };
  }

  /**
   * OpenAI Codex Device Flow 인증 시작
   */
  async startCodexDeviceFlow(userAccessToken: string): Promise<DeviceAuthInitResponse> {
    const url = `${this.baseUrl}/api/v1/codex/device/start`;
    const response = await fetch(url, {
      method: "POST",
      headers: { Authorization: `Bearer ${userAccessToken}` },
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) {
      throw new Error(`Failed to start Codex Device Flow: ${response.statusText}`);
    }
    return (await response.json()) as DeviceAuthInitResponse;
  }

  /**
   * OpenAI Codex Device Flow 완료 확인 및 토큰 저장
   */
  async checkCodexDeviceFlow(
    userAccessToken: string,
    deviceAuthId: string,
    userCode: string,
  ): Promise<any> {
    const url = `${this.baseUrl}/api/v1/codex/device/check`;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${userAccessToken}`,
      },
      body: JSON.stringify({
        deviceAuthId,
        userCode,
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.message || err.error || "Device auth pending or failed");
    }
    return response.json();
  }

  /** IAM derives the tenant from this delegated user JWT. */
  async saveApiKey(
    userAccessToken: string,
    provider: "OPENAI_API_KEY" | "EMBEDDING_API_KEY",
    apiKey: string,
  ): Promise<any> {
    const url = `${this.baseUrl}/api/v1/credentials/ai-keys`;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${userAccessToken}`,
      },
      body: JSON.stringify({
        provider,
        apiKey,
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.message || err.error || "Failed to save API key");
    }
    return response.json();
  }

  /** IAM derives the tenant from this delegated user JWT. */
  async deleteApiKey(
    userAccessToken: string,
    provider: "OPENAI_API_KEY" | "EMBEDDING_API_KEY" | "CODEX_OAUTH",
  ): Promise<boolean> {
    const url = `${this.baseUrl}/api/v1/credentials/ai-keys`;
    const response = await fetch(url, {
      method: "DELETE",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${userAccessToken}`,
      },
      body: JSON.stringify({
        provider,
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    return response.ok;
  }
}
