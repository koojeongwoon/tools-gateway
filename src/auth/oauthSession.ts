import {
  createHash,
  randomBytes,
} from "node:crypto";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { RedisClientType } from "redis";

export interface OAuthConfig {
  authServerUrl: string;
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  signoutUrl: string;
  clientId: string;
  clientSecret: string;
  tenantId: string;
  redirectUri: string;
  scope: string;
  sessionTtlSeconds: number;
  loginTtlSeconds: number;
}

interface SessionRecord {
  subject: string;
  email?: string;
  name?: string;
  /**
   * IAM delegated token for server-side calls made on behalf of this session.
   * It is retained only in the opaque Redis session and is never returned by
   * the Gateway HTTP API.
   */
  iamAccessToken: string;
  iamAccessTokenExpiresAt: number;
  expiresAt: number;
}

export interface GatewaySession {
  subject: string;
  email?: string;
  name?: string;
  /** Server-internal delegated IAM credential; never serialize this to clients. */
  iamAccessToken?: string;
}

export function loadOAuthConfig(environment: NodeJS.ProcessEnv = process.env): OAuthConfig | undefined {
  if (environment.SSO_ENABLED !== "true") return undefined;
  const required = (name: string): string => {
    const value = environment[name]?.trim();
    if (!value) throw new Error(`${name} is required when SSO_ENABLED=true`);
    return value;
  };
  const authServerUrl = (environment.AUTH_SERVER_URL ?? "https://auth.snappytory.com").replace(/\/$/, "");
  const tenantId = environment.TOOLS_GATEWAY_TENANT_ID ?? "ten_9664c024babc4110";
  const tenantIssuer = `${authServerUrl}/t/${tenantId}`;
  const configuredIssuer = environment.AUTH_TOKEN_ISSUER?.replace(/\/$/, "");
  if (configuredIssuer && configuredIssuer !== tenantIssuer) {
    throw new Error("AUTH_TOKEN_ISSUER must match the configured Tools Gateway tenant issuer");
  }
  const clientId = required("TOOLS_GATEWAY_CLIENT_ID");
  const signout = new URL(`/portal/tenants/${encodeURIComponent(tenantId)}/signout`, authServerUrl);
  signout.searchParams.set("clientId", clientId);
  return {
    authServerUrl,
    issuer: tenantIssuer,
    authorizationEndpoint: `${tenantIssuer}/oauth2/authorize`,
    tokenEndpoint: `${tenantIssuer}/oauth2/token`,
    jwksUri: `${tenantIssuer}/oauth2/jwks`,
    signoutUrl: signout.toString(),
    clientId,
    clientSecret: required("TOOLS_GATEWAY_CLIENT_SECRET"),
    tenantId,
    redirectUri: environment.TOOLS_GATEWAY_REDIRECT_URI ?? "https://tools-gateway.lynply.com/api/v1/auth/sso-callback",
    scope: environment.TOOLS_GATEWAY_OAUTH_SCOPE ?? "openid profile email",
    sessionTtlSeconds: Number(environment.GATEWAY_SESSION_TTL_SECONDS ?? 2_592_000),
    loginTtlSeconds: Number(environment.OAUTH_LOGIN_TTL_SECONDS ?? 300),
  };
}

export class OAuthSessionStore {
  private readonly jwks: ReturnType<typeof createRemoteJWKSet>;

  constructor(
    private readonly redis: RedisClientType,
    private readonly config: OAuthConfig,
  ) {
    this.jwks = createRemoteJWKSet(new URL(config.jwksUri));
  }

  async beginLogin(): Promise<{ authorizationUrl: string }> {
    const state = randomBytes(32).toString("base64url");
    const verifier = randomBytes(64).toString("base64url");
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    await this.redis.set(this.loginKey(state), verifier, { EX: this.config.loginTtlSeconds });
    const query = new URLSearchParams({
      response_type: "code",
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scope,
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
    });
    return { authorizationUrl: `${this.config.authorizationEndpoint}?${query}` };
  }

  async completeLogin(code: string, state: string): Promise<{ sessionId: string; principal: GatewaySession }> {
    const verifier = await this.redis.getDel(this.loginKey(state));
    if (!verifier) throw new Error("OAuth login state is missing or expired");
    const tokenRequest = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.config.redirectUri,
      code_verifier: verifier,
      client_id: this.config.clientId,
    });
    const response = await fetch(this.config.tokenEndpoint, {
      method: "POST",
      headers: {
        authorization: `Basic ${Buffer.from(`${this.config.clientId}:${this.config.clientSecret}`).toString("base64")}`,
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body: tokenRequest,
    });
    if (!response.ok) throw new Error("OAuth code exchange failed");
    const payload = await response.json() as Record<string, unknown>;
    const tokenSet = await this.validateTokens(payload);
    const sessionId = randomBytes(32).toString("base64url");
    await this.redis.set(this.sessionKey(sessionId), JSON.stringify(tokenSet), {
      EX: this.config.sessionTtlSeconds,
    });
    return { sessionId, principal: this.principal(tokenSet) };
  }

  async resolve(sessionId: string): Promise<GatewaySession | undefined> {
    const encrypted = await this.redis.get(this.sessionKey(sessionId));
    if (!encrypted) return undefined;
    try {
      const session = JSON.parse(encrypted) as SessionRecord;
      if (session.expiresAt <= Math.floor(Date.now() / 1000)) {
        await this.redis.del(this.sessionKey(sessionId));
        return undefined;
      }
      return this.principal(session);
    } catch {
      await this.redis.del(this.sessionKey(sessionId));
      return undefined;
    }
  }

  async revoke(sessionId: string): Promise<void> {
    await this.redis.del(this.sessionKey(sessionId));
  }

  getSignoutUrl(): string {
    return this.config.signoutUrl;
  }

  private async validateTokens(payload: Record<string, unknown>): Promise<SessionRecord> {
    if (typeof payload.access_token !== "string") {
      throw new Error("OAuth token response is incomplete");
    }
    const verified = await jwtVerify(payload.access_token, this.jwks, {
      issuer: this.config.issuer,
      audience: this.config.clientId,
      algorithms: ["RS256"],
    });
    const accessClaims: JWTPayload & { client_id?: string; tenant_id?: string; email?: string; name?: string } = verified.payload;
    const idClaims = typeof payload.id_token === "string"
      ? (await jwtVerify(payload.id_token, this.jwks, {
          issuer: this.config.issuer,
          audience: this.config.clientId,
          algorithms: ["RS256"],
        })).payload as JWTPayload & { email?: string; name?: string }
      : undefined;
    const claims = { ...accessClaims, email: idClaims?.email ?? accessClaims.email, name: idClaims?.name ?? accessClaims.name };
    if (
      claims.client_id !== this.config.clientId
      || claims.tenant_id !== this.config.tenantId
      || !claims.sub
      || !claims.exp
    ) {
      throw new Error("OAuth token claims do not belong to Tools Gateway");
    }
    return {
      subject: claims.sub,
      ...(claims.email ? { email: claims.email } : {}),
      ...(claims.name ? { name: claims.name } : {}),
      iamAccessToken: payload.access_token,
      iamAccessTokenExpiresAt: claims.exp,
      expiresAt: Math.floor(Date.now() / 1000) + this.config.sessionTtlSeconds,
    };
  }

  private principal(session: SessionRecord): GatewaySession {
    return {
      subject: session.subject,
      ...(session.email ? { email: session.email } : {}),
      ...(session.name ? { name: session.name } : {}),
      ...(session.iamAccessTokenExpiresAt > Math.floor(Date.now() / 1000)
        ? { iamAccessToken: session.iamAccessToken }
        : {}),
    };
  }

  private loginKey(value: string): string { return `tg:oauth:login:${this.hash(value)}`; }
  private sessionKey(value: string): string { return `tg:web:session:${this.hash(value)}`; }
  private hash(value: string): string { return createHash("sha256").update(value).digest("hex"); }

}
