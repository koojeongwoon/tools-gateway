import { z } from "zod";
import type { Authority } from "./jobs/store.js";
import type { ManagementConfig } from "./config.js";
import { ManagementError, unavailable, type DeviceAuthorizer, type Identity } from "./model.js";

// Pin all endpoints to server configuration; no redirects and bounded time/body.
export async function boundedFetch(url: string, options: RequestInit = {}): Promise<Response> {
  if (new URL(url).protocol !== "https:") throw unavailable();
  const response = await fetch(url, { ...options, redirect: "error", signal: AbortSignal.timeout(3000) });
  const reader = response.body?.getReader();
  const chunks: Uint8Array[] = []; let length = 0;
  if (reader) try {
    while (true) { const next = await reader.read(); if (next.done) break;
      length += next.value.length; if (length > 65536) throw unavailable(); chunks.push(next.value); }
  } finally { await reader.cancel(); }
  return new Response(Buffer.concat(chunks), { status: response.status, headers: response.headers });
}
export class IamDeviceReader implements DeviceAuthorizer {
  private token: { value: string; until: number } | undefined;
  private readonly cache = new Map<string, number>();
  constructor(private readonly config: ManagementConfig, private readonly request = boundedFetch,
    private readonly clock = () => performance.now(), private readonly cacheMs = 15000) {}
  async authorize(identity: Identity): Promise<void> {
    const key = JSON.stringify(identity), start = this.clock();
    const cached = this.cache.get(key);
    if (cached !== undefined && start >= cached && start - cached < this.cacheMs) return;
    this.cache.delete(key);
    try {
      const token = await this.readerToken();
      const response = await this.request(`${this.config.issuer}/api/v1/device-status/check`, {
        method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ device_id: identity.device, subject: identity.subject, client_id: identity.client, resource: identity.resource }),
      });
      if (response.status === 403 || response.status === 404) throw new ManagementError(403, "device_not_authorized");
      if (!response.ok) { if (response.status === 401) this.token = undefined; throw unavailable(); }
      const p = await response.json() as Record<string, unknown>;
      if (p.device_id !== identity.device || p.subject !== identity.subject || p.tenant_id !== identity.tenant
        || p.organization_id !== identity.organization || p.device_version !== identity.version || p.key_jkt !== identity.jkt
        || p.user_version !== identity.userVersion || p.service_access_version !== identity.serviceVersion
        || p.status !== "ACTIVE" || p.authorized !== true || !Number.isSafeInteger(p.checked_at)) {
        throw new ManagementError(403, "device_not_authorized");
      }
      const end = this.clock();
      if (end < start || end - start >= 15000) throw unavailable();
      if (this.cache.size >= 10000) this.cache.clear();
      this.cache.set(key, start);
    } catch (error) { if (error instanceof ManagementError) throw error; throw unavailable(); }
  }
  async authority(subject: string, organization: string, gatewayClient: string): Promise<Authority> {
    try {
      const token = await this.readerToken();
      const response = await this.request(`${this.config.issuer}/api/v1/device-status/management-authority`, {
        method:"POST", headers:{authorization:`Bearer ${token}`,"content-type":"application/json"},
        body:JSON.stringify({subject,organization_id:organization,client_id:gatewayClient}),
      });
      if(response.status===403 || response.status===404) throw new ManagementError(403,"job_not_authorized");
      if(!response.ok) { if(response.status===401) this.token=undefined; throw unavailable(); }
      const version=z.string().regex(/^[1-9][0-9]{0,18}$/);
      const result=z.object({tenant_id:z.literal(this.config.tenant),subject:z.literal(subject),
        organization_id:z.literal(organization),client_id:z.literal(gatewayClient),role:z.literal("ORG_ADMIN"),
        authorized:z.literal(true),user_version:version,service_access_version:version,
        checked_at:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)}).strict().safeParse(await response.json());
      const now=Math.floor(Date.now()/1000);
      if(!result.success || result.data.checked_at>now+5 || result.data.checked_at<now-5) throw unavailable();
      return result.data;
    } catch(error) { if(error instanceof ManagementError) throw error; throw unavailable(); }
  }
  private async readerToken(): Promise<string> {
    const start = this.clock();
    if (this.token && start < this.token.until && start >= this.token.until - 300000) return this.token.value;
    this.token = undefined;
    const basic = Buffer.from(`${encodeURIComponent(this.config.readerClient)}:${encodeURIComponent(this.config.readerSecret)}`).toString("base64");
    const response = await this.request(`${this.config.issuer}/oauth2/token`, { method: "POST",
      headers: { authorization: `Basic ${basic}`, "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "client_credentials", scope: "iam:device-status:read", resource: `${this.config.issuer}/api/v1/device-status` }).toString() });
    if (!response.ok) throw unavailable();
    const p = await response.json() as Record<string, unknown>;
    if (p.token_type !== "Bearer" || typeof p.access_token !== "string" || p.access_token.length > 16384 || !p.access_token
      || typeof p.expires_in !== "number" || p.expires_in <= 0 || p.expires_in > 300 || p.refresh_token) throw unavailable();
    this.token = { value: p.access_token, until: start + p.expires_in * 1000 - 5000 };
    return this.token.value;
  }
}
