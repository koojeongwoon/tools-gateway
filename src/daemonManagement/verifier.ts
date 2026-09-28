import { createHash } from "node:crypto";
import { calculateJwkThumbprint, compactVerify, createRemoteJWKSet, customFetch, decodeProtectedHeader,
  importJWK, jwtVerify, type JWTVerifyGetKey } from "jose";
import type { ManagementConfig } from "./config.js";
import { ManagementError, unavailable, type Identity, type ManagementStore } from "./model.js";
import { boundedFetch } from "./iamReader.js";
export const hash = (value: string) => createHash("sha256").update(value).digest("base64url");
const text = (x: unknown): x is string => typeof x === "string" && x.length > 0 && x.length <= 255;
const version = (x: unknown): x is string => typeof x === "string" && /^[1-9][0-9]{0,18}$/.test(x);
const obj = (x: unknown): x is Record<string, unknown> => !!x && typeof x === "object" && !Array.isArray(x);

export class ManagementVerifier {
  private readonly keys: JWTVerifyGetKey;
  constructor(private readonly config: ManagementConfig, private readonly store: ManagementStore,
    keys?: JWTVerifyGetKey, private readonly now = () => Date.now()) {
    this.keys = keys ?? createRemoteJWKSet(new URL(`${config.issuer}/oauth2/jwks`), {
      timeoutDuration: 3000, [customFetch]: async (url, options) => boundedFetch(String(url), options),
    });
  }
  async verify(authorization: unknown, rawProof: unknown, purpose: "report" | "jobs" = "report"): Promise<Identity> {
    if (typeof authorization !== "string" || !/^DPoP [A-Za-z0-9_.-]+$/.test(authorization) || authorization.length > 16384) {
      throw new ManagementError(401, "invalid_token");
    }
    const token = authorization.slice(5), now = Math.floor(this.now() / 1000);
    let identity: Identity;
    try {
      const { payload: p, protectedHeader: h } = await jwtVerify(token, this.keys, {
        algorithms: ["RS256"], typ: "at+jwt", issuer: this.config.issuer,
        audience: this.config.resource, currentDate: new Date(this.now()),
      });
      const d = p["https://lynply.com/claims/device"];
      const aud = Array.isArray(p.aud) ? p.aud : [p.aud];
      if (!text(h.kid) || h.jku || h.x5u || h.jwk || h.crit || aud.length !== 1
        || p.client_id !== this.config.client || p.tenant_id !== this.config.tenant
        || !text(p.sub) || !text(p.active_organization_id) || !text(p.jti)
        || !Number.isSafeInteger(p.iat) || !Number.isSafeInteger(p.exp)
        || p.iat! > now + 5 || p.exp! <= now || p.exp! > p.iat! + 300 || p.exp! <= p.iat!
        || !obj(d) || d.v !== 1 || !text(d.id) || !Number.isSafeInteger(d.version) || Number(d.version) < 1
        || !obj(p.cnf) || typeof p.cnf.jkt !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(p.cnf.jkt)
        || !version(p.user_version) || !version(p.service_access_version)) throw new Error();
      if (typeof p.scope !== "string" || !["device:identity", purpose === "report" ? "gateway:daemon:report" : "gateway:daemon:jobs:read"].every(s => p.scope!.toString().split(" ").includes(s))) {
        throw new ManagementError(403, "insufficient_scope");
      }
      identity = { issuer: this.config.issuer, tenant: this.config.tenant, resource: this.config.resource,
        client: this.config.client, subject: p.sub, organization: p.active_organization_id,
        device: d.id, version: Number(d.version), jkt: p.cnf.jkt, userVersion: p.user_version, serviceVersion: p.service_access_version };
    } catch (error) {
      if (error instanceof ManagementError) throw error;
      // Never include tokens or JOSE error details in responses/logs.
      if (error instanceof Error && (error.name === "TimeoutError" || error.name === "JWKSTimeout" || error instanceof TypeError)) throw unavailable();
      throw new ManagementError(401, "invalid_token");
    }
    let p: Record<string, unknown>;
    try {
      if (typeof rawProof !== "string" || rawProof.length > 8192) throw new Error();
      const h = decodeProtectedHeader(rawProof);
      if (h.typ !== "dpop+jwt" || h.alg !== "ES256" || !h.jwk || h.jku || h.x5u || h.crit
        || Object.keys(h).some(k => !["typ", "alg", "jwk"].includes(k))) throw new Error();
      const jwk = h.jwk;
      if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y
        || Object.keys(jwk).some(k => !["kty", "crv", "x", "y"].includes(k))
        || await calculateJwkThumbprint(jwk) !== identity.jkt) throw new Error();
      const verified = await compactVerify(rawProof, await importJWK(jwk, "ES256"), { algorithms: ["ES256"] });
      p = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(verified.payload)) as Record<string, unknown>;
      if (!obj(p) || !text(p.jti) || !Number.isSafeInteger(p.iat) || Number(p.iat) < now - 60 || Number(p.iat) > now + 5
        || p.htm !== (purpose === "report" ? "POST" : "GET") || p.htu !== `${this.config.resource}/${purpose === "report" ? "reports" : "jobs/pending"}` || p.ath !== hash(token)) throw new Error();
    } catch { throw new ManagementError(401, "invalid_dpop_proof"); }
    try {
      if (!text(p.nonce) || !await this.store.validNonce(this.config.resource, identity.jkt, p.nonce)) {
        throw new ManagementError(401, "use_dpop_nonce", await this.store.issueNonce(this.config.resource, identity.jkt));
      }
      if (!await this.store.consumeProof(this.config.resource, identity.jkt, p.jti as string)) throw new ManagementError(401, "invalid_dpop_proof");
    } catch (error) { if (error instanceof ManagementError) throw error; throw unavailable(); }
    return identity;
  }
}
