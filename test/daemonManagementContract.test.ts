import { readFileSync } from "node:fs";
import { beforeAll, expect, it, vi } from "vitest";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, calculateJwkThumbprint } from "jose";
import { ManagementVerifier, hash } from "../src/daemonManagement/verifier.js";
import { IamDeviceReader } from "../src/daemonManagement/iamReader.js";
import type { ManagementStore } from "../src/daemonManagement/model.js";
const fixture = JSON.parse(readFileSync(new URL("./fixtures/daemon-management-v1/examples.json", import.meta.url), "utf8"));
const cases = JSON.parse(readFileSync(new URL("./fixtures/daemon-management-v1/cases.json", import.meta.url), "utf8"));
const config = { issuer: fixture.trust.issuer, resource: fixture.trust.resource, client: fixture.trust.client_id, tenant: fixture.trust.tenant_id, readerClient: "reader", readerSecret: "test" };
let rsa: Awaited<ReturnType<typeof generateKeyPair>>, ec: Awaited<ReturnType<typeof generateKeyPair>>;
beforeAll(async () => { rsa = await generateKeyPair("RS256"); ec = await generateKeyPair("ES256"); });
function db(nonce: string): ManagementStore {
  return { issueNonce: vi.fn(async () => nonce), validNonce: vi.fn(async (_v,_k,n) => n === nonce), consumeProof: vi.fn(async () => true), accept: vi.fn(), list: vi.fn() };
}
it("verifies the original shared public token/proof fixture without replacing its signature", async () => {
  const f = fixture.management;
  const i = await new ManagementVerifier(config, db(f.context.nonce), createLocalJWKSet(fixture.trust.jwks), () => fixture.now*1000).verify(f.request.headers.Authorization, f.request.headers.DPoP);
  expect(i.device).toBe("device-fixture");
});
it.each(cases.management_vectors as { id: string; changes: Record<string, unknown>; expected: { http: number; error?: string; header?: string } }[])("$id executes the shared management acceptance case", async vector => {
  const f = structuredClone(fixture.management);
  for (const [path, raw] of Object.entries(vector.changes)) {
    const value = raw === "$now" ? fixture.now : raw === "$now-61" ? fixture.now-61 : raw === "$now+6" ? fixture.now+6 : raw;
    const parts = path.replace(/^device_claim/, "token_claims.DEVICE").split(".");
    let target = f;
    while (parts.length > 1) { const k = parts.shift()!; target = k === "DEVICE" ? target["https://lynply.com/claims/device"] : target[k]; }
    const key = parts[0] === "DEVICE" ? "https://lynply.com/claims/device" : parts[0]!;
    target[key] = value;
  }
  const publicKey = await exportJWK(ec.publicKey); const jkt = await calculateJwkThumbprint(publicKey);
  f.token_claims.cnf.jkt = jkt;
  if (!("status_response.key_jkt" in vector.changes)) f.status_response.key_jkt = jkt;
  const token = await new SignJWT(f.token_claims).setProtectedHeader(f.token_header).sign(rsa.privateKey);
  f.proof_claims.ath = "proof_claims.ath" in vector.changes ? f.proof_claims.ath : hash(token);
  const proofKey = f.proof_signer ? await generateKeyPair("ES256") : ec;
  let proof = await new SignJWT(f.proof_claims).setProtectedHeader({ typ: "dpop+jwt", alg: "ES256", jwk: await exportJWK(proofKey.publicKey) }).sign(proofKey.privateKey);
  if (f.proof_signature) { const parts = proof.split("."); const sig = Buffer.from(parts[2]!, "base64url"); sig[0] = sig[0]! ^ 1; parts[2] = sig.toString("base64url"); proof = parts.join("."); }
  const store = db(f.context.nonce);
  store.consumeProof = async () => { if (f.context.replay_store_available === false) throw new Error(); return !f.context.seen_proof_jtis.includes(f.proof_claims.jti); };
  const keys = createLocalJWKSet({ keys: [{ ...await exportJWK(rsa.publicKey), kid: f.token_header.kid }] });
  let clock = 0;
  const request = vi.fn(async (url: string) => {
    if (url.endsWith("/token")) return new Response(JSON.stringify({ token_type: "Bearer", access_token: "synthetic", expires_in: 300 }));
    if (clock > 15000 && f.context.iam_available === false) throw new Error();
    return new Response(JSON.stringify(f.status_response));
  });
  const reader = new IamDeviceReader(config, request, () => clock);
  let result: { status: number; code?: string; nonce?: string } = { status: 202 };
  try {
    const auth = vector.id === "M02" ? `Bearer ${token}` : `DPoP ${token}`;
    const i = await new ManagementVerifier(config, store, keys, () => fixture.now*1000).verify(auth, vector.id === "M03" ? undefined : proof);
    if (vector.id === "M24") { await reader.authorize(i); clock = 16000; }
    await reader.authorize(i);
  } catch (error) { result = error as typeof result; }
  expect(result.status).toBe(vector.expected.http);
  if (vector.expected.error) expect(result.code).toBe(vector.expected.error);
  if (vector.expected.header) expect(result.nonce).toBeTruthy();
});
