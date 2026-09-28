import { createHash } from "node:crypto";
import { compactVerify, importJWK } from "jose";
import { z } from "zod";

export const JOB_TYPE = "lynply-daemon-job+jws";
export const JOB_AUDIENCE = "urn:lynply:tools-daemon:management-jobs:v1";
export const MAX_JOB_BYTES = 16384;
const MAX_INTEGER = Number.MAX_SAFE_INTEGER;
const id = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);
const positive = z.number().int().min(1).max(MAX_INTEGER);
const timestamp = z.number().int().min(0).max(MAX_INTEGER);
const url = z.string().max(512).regex(/^[\x21-\x7e]+$/).refine(value => {
  try { const u = new URL(value); return u.protocol === "https:" && !u.username && !u.password && !u.search && !u.hash && u.href === value; }
  catch { return false; }
});
const digest = z.string().regex(/^[a-f0-9]{64}$/);
export const resourceSchema = z.object({ id, version: positive, sha256: digest }).strict();
export const jobSchema = z.object({
  schema_version: z.literal(1), job_id: id, iss: url, aud: z.literal(JOB_AUDIENCE),
  identity_issuer: url, tenant_id: id, organization_id: id, subject: id,
  device_id: id, device_version: positive, key_jkt: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  approved_by: z.object({ subject: id, authorization_id: id, approved_at: timestamp }).strict(),
  operation: z.literal("managed_worker.revoke"), resource: resourceSchema,
  policy_revision: positive, expected_state_version: positive, iat: timestamp, exp: timestamp,
}).strict();
export type ManagementJob = z.infer<typeof jobSchema>;
export interface JobBinding {
  gateway: string; identityIssuer: string; tenant: string; organization: string;
  subject: string; device: string; deviceVersion: number; jkt: string;
}
export interface JobTrust { kid: string; publicKey: string }
export interface ResourceState {
  resource: z.infer<typeof resourceSchema>; policy_revision: number;
  state_version: number; status: "active" | "revoked";
}
export interface PriorJob { job_id: string; digest: string }
export type Admission = { decision: "already_recorded"; job_id: string; digest: string }
  | { decision: "prepare_revoke"; job_id: string; digest: string; resource_id: string;
      expected_state_version: number; next_state_version: number };
export class JobError extends Error {
  constructor(readonly code: string) { super(code); }
}
function fail(code: string): never { throw new JobError(code); }

// v1 canonical subset: ASCII strings, integers, fixed schema, sorted object keys,
// no whitespace. This is not a general-purpose RFC 8785 implementation.
export function canonicalJobJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJobJson).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalJobJson((value as Record<string,unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(value);
}
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
function decode(segment: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) fail("job_invalid");
  const bytes = Buffer.from(segment, "base64url");
  if (bytes.toString("base64url") !== segment) fail("job_invalid");
  return bytes;
}
function parseCanonical(bytes: Uint8Array): unknown {
  try {
    const raw = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const value: unknown = JSON.parse(raw);
    if (canonicalJobJson(value) !== raw) fail("job_invalid");
    return value;
  } catch { return fail("job_invalid"); }
}
const headerSchema = z.object({ alg: z.literal("EdDSA"), typ: z.literal(JOB_TYPE), kid: id }).strict();
const stateSchema = z.object({ resource: resourceSchema, policy_revision: positive, state_version: positive, status: z.enum(["active", "revoked"]) }).strict();
const priorSchema = z.object({ job_id: id, digest }).strict();

export class VerifiedJob {
  private constructor(private readonly job: ManagementJob, readonly digest: string, private readonly verifiedAt: number) {}

  static async verify(compact: string, trust: JobTrust, binding: JobBinding, now: number): Promise<VerifiedJob> {
    if (typeof compact !== "string" || compact.length > MAX_JOB_BYTES || !Number.isSafeInteger(now) || now < 0) fail("job_invalid");
    const segments = compact.split(".");
    if (segments.length !== 3) fail("job_invalid");
    const header = headerSchema.safeParse(parseCanonical(decode(segments[0]!)));
    if (!header.success) fail("job_invalid");
    if (header.data.kid !== trust.kid || !id.safeParse(trust.kid).success || !/^[A-Za-z0-9_-]{43}$/.test(trust.publicKey)
      || Buffer.from(trust.publicKey, "base64url").toString("base64url") !== trust.publicKey) fail("job_key_untrusted");
    const payload = decode(segments[1]!);
    const signature = decode(segments[2]!);
    if (signature.length !== 64) fail("job_signature_invalid");
    try {
      const key = await importJWK({ kty: "OKP", crv: "Ed25519", x: trust.publicKey }, "EdDSA");
      await compactVerify(compact, key, { algorithms: ["EdDSA"] });
    } catch { fail("job_signature_invalid"); }
    const parsed = jobSchema.safeParse(parseCanonical(payload));
    if (!parsed.success) fail("job_invalid");
    const job = parsed.data;
    if (job.exp <= job.iat || job.exp - job.iat > 300 || job.approved_by.approved_at > job.iat
      || job.iat - job.approved_by.approved_at > 300) fail("job_invalid");
    if (job.iss !== binding.gateway || job.identity_issuer !== binding.identityIssuer || job.tenant_id !== binding.tenant
      || job.organization_id !== binding.organization || job.subject !== binding.subject || job.device_id !== binding.device
      || job.device_version !== binding.deviceVersion || job.key_jkt !== binding.jkt) fail("job_binding_mismatch");
    if (job.iat > now + 5) fail("job_not_yet_valid");
    if (job.exp <= now) fail("job_expired");
    return new VerifiedJob(job, hash(payload), now);
  }

  // Pure planning only. The caller must atomically persist the intent + state CAS
  // before any effect, and independently authorize the approver before signing.
  plan(current: ResourceState, now: number, prior?: PriorJob): Admission {
    if (!Number.isSafeInteger(now) || now < 0) fail("job_invalid");
    if (now < this.verifiedAt) fail("job_clock_regressed");
    if (this.job.iat > now + 5) fail("job_not_yet_valid");
    if (this.job.exp <= now) fail("job_expired");
    if (!stateSchema.safeParse(current).success || (prior && !priorSchema.safeParse(prior).success)) fail("job_state_invalid");
    const job = this.job;
    if (prior) {
      if (prior.job_id !== job.job_id || prior.digest !== this.digest) fail("job_conflict");
      return { decision: "already_recorded", job_id: job.job_id, digest: this.digest };
    }
    if (canonicalJobJson(current.resource) !== canonicalJobJson(job.resource)) fail("job_resource_mismatch");
    if (current.policy_revision !== job.policy_revision || current.state_version !== job.expected_state_version) fail("job_stale_state");
    if (current.status !== "active") fail("job_resource_revoked");
    if (current.state_version === MAX_INTEGER) fail("job_state_invalid");
    return { decision: "prepare_revoke", job_id: job.job_id, digest: this.digest, resource_id: job.resource.id,
      expected_state_version: current.state_version, next_state_version: current.state_version + 1 };
  }
}
