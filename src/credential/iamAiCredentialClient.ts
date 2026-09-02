/**
 * IAM 중앙 인증 서버로부터 유저/조직의 AI 자격증명(Codex Token, OpenAI API Key, Embedding API Key)을
 * 조회하고 등록/수정/Device Flow를 수행하는 클라이언트.
 */

export interface AiBundle {
  user_id?: string;
  org_id?: string;
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

  constructor(baseUrl?: string, timeoutMs: number = 5000) {
    this.baseUrl = (baseUrl || process.env.IAM_SERVER_URL || "http://localhost:8080").replace(/\/$/, "");
    this.timeoutMs = timeoutMs;
  }

  /**
   * IAM 서버에서 AI 자격증명 번들을 조회합니다.
   */
  async getAiBundle(userId?: string, orgId?: string): Promise<AiBundle | null> {
    const params = new URLSearchParams();
    if (userId) params.set("user_id", userId);
    if (orgId) params.set("org_id", orgId);

    const url = `${this.baseUrl}/api/v1/credentials/ai-bundle?${params.toString()}`;

    try {
      const response = await fetch(url, {
        method: "GET",
        signal: AbortSignal.timeout(this.timeoutMs),
      });

      if (!response.ok) {
        return null;
      }

      return (await response.json()) as AiBundle;
    } catch (err) {
      console.warn(`[IamAiCredentialClient] Failed to fetch AI bundle from ${this.baseUrl}:`, err);
      return null;
    }
  }

  /**
   * 유효한 OpenAI API Key를 단일 획득합니다 (없을 경우 환경변수 fallback)
   */
  async getOpenAiApiKey(userId?: string, orgId?: string): Promise<string | undefined> {
    const bundle = await this.getAiBundle(userId, orgId);
    if (bundle?.openai_api_key?.configured && bundle.openai_api_key.api_key) {
      return bundle.openai_api_key.api_key;
    }
    return process.env.OPENAI_API_KEY;
  }

  /**
   * 유효한 Embedding API Key를 단일 획득합니다 (없을 경우 OpenAI Key fallback)
   */
  async getEmbeddingApiKey(userId?: string, orgId?: string): Promise<string | undefined> {
    const bundle = await this.getAiBundle(userId, orgId);
    if (bundle?.embedding_api_key?.configured && bundle.embedding_api_key.api_key) {
      return bundle.embedding_api_key.api_key;
    }
    return this.getOpenAiApiKey(userId, orgId);
  }

  /**
   * 유효한 Codex Access Token을 단일 획득합니다.
   */
  async getCodexAccessToken(userId?: string, orgId?: string): Promise<string | undefined> {
    const bundle = await this.getAiBundle(userId, orgId);
    if (bundle?.codex?.linked && bundle.codex.access_token) {
      return bundle.codex.access_token;
    }
    return undefined;
  }

  /**
   * OpenAI Codex Device Flow 인증 시작
   */
  async startCodexDeviceFlow(): Promise<DeviceAuthInitResponse> {
    const url = `${this.baseUrl}/api/v1/codex/device/start`;
    const response = await fetch(url, {
      method: "POST",
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
    deviceAuthId: string,
    userCode: string,
    userId?: string,
    orgId?: string,
    accountType: "USER" | "ORGANIZATION" = "USER"
  ): Promise<any> {
    const url = `${this.baseUrl}/api/v1/codex/device/check`;
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        deviceAuthId,
        userCode,
        userId,
        orgId,
        accountType,
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.message || err.error || "Device auth pending or failed");
    }
    return response.json();
  }

  /**
   * AI API Key (OpenAI / Embedding) 저장
   */
  async saveApiKey(
    provider: "OPENAI_API_KEY" | "EMBEDDING_API_KEY",
    apiKey: string,
    userId?: string,
    orgId?: string,
    accountType: "USER" | "ORGANIZATION" = "USER"
  ): Promise<any> {
    const url = `${this.baseUrl}/api/v1/credentials/ai-keys`;
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        userId,
        orgId,
        accountType,
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

  /**
   * AI API Key 또는 자격증명 삭제
   */
  async deleteApiKey(
    provider: "OPENAI_API_KEY" | "EMBEDDING_API_KEY" | "CODEX_OAUTH",
    userId?: string,
    orgId?: string,
    accountType: "USER" | "ORGANIZATION" = "USER"
  ): Promise<boolean> {
    const url = `${this.baseUrl}/api/v1/credentials/ai-keys`;
    const response = await fetch(url, {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        userId,
        orgId,
        accountType,
        provider,
      }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    return response.ok;
  }
}
