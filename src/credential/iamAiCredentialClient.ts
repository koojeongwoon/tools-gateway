/**
 * IAM 중앙 인증 서버로부터 유저/조직의 AI 자격증명(Codex Token, OpenAI API Key, Embedding API Key)을
 * 원스톱으로 조회하는 클라이언트.
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

export class IamAiCredentialClient {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(baseUrl?: string, timeoutMs: number = 5000) {
    this.baseUrl = (baseUrl || process.env.IAM_SERVER_URL || 'http://localhost:8080').replace(/\/$/, '');
    this.timeoutMs = timeoutMs;
  }

  /**
   * IAM 서버에서 AI 자격증명 번들을 조회합니다.
   */
  async getAiBundle(userId?: string, orgId?: string): Promise<AiBundle | null> {
    const params = new URLSearchParams();
    if (userId) params.set('user_id', userId);
    if (orgId) params.set('org_id', orgId);

    const url = `${this.baseUrl}/api/v1/credentials/ai-bundle?${params.toString()}`;

    try {
      const response = await fetch(url, {
        method: 'GET',
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
   * 유효한 Codex Access Token을 단일 획득합니다.
   */
  async getCodexAccessToken(userId?: string, orgId?: string): Promise<string | undefined> {
    const bundle = await this.getAiBundle(userId, orgId);
    if (bundle?.codex?.linked && bundle.codex.access_token) {
      return bundle.codex.access_token;
    }
    return undefined;
  }
}
