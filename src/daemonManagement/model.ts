import { z } from "zod";

export class ManagementError extends Error {
  constructor(readonly status: number, readonly code: string, readonly nonce?: string) {
    super(code);
  }
}
export const unavailable = () => new ManagementError(503, "authorization_state_unavailable");
const id = z.string().min(1).max(255).regex(/^[A-Za-z0-9._:-]+$/);
const integer = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const revision = integer.nullable();
export const reportSchema = z.object({
  schema_version: z.literal(1),
  report_id: id,
  sequence: integer,
  observed_at: z.iso.datetime({ offset: true }),
  status: z.object({
    connection: z.enum(["connected", "unavailable"]),
    daemon_version: z.string().regex(/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/).max(64).optional(),
    scope: z.literal("native_mcp_worker").optional(),
    policy: z.object({ state: z.enum(["valid", "expired", "unverified"]), revision }).strict().optional(),
    execution: z.object({ state: z.enum(["preflight_passed", "blocked", "unverified"]) }).strict().optional(),
    job_results: z.array(z.object({
      job_id: id, digest: z.string().regex(/^[a-f0-9]{64}$/), resource_id: id,
      state_version: integer, admission: z.literal("blocked"),
      termination: z.enum(["confirmed", "unknown"]),
    }).strict()).max(20).optional(),
    recent_events: z.array(z.object({
      sequence: integer,
      kind: z.enum(["denied", "intent", "completed", "failed", "interrupted"]),
      timestamp: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
      policy_revision: revision,
    }).strict()).max(20).optional(),
  }).strict(),
}).strict();
export type Report = z.infer<typeof reportSchema>;
export interface Identity {
  issuer: string; tenant: string; subject: string; organization: string;
  client: string; resource: string; device: string; version: number; jkt: string;
  userVersion: string; serviceVersion: string;
}
export interface Receipt { report_id: string; sequence: number; received_at: string }
export interface StoredReport { identity: Identity; report: Report; receipt: Receipt }
export interface ManagementStore {
  issueNonce(verifier: string, jkt: string): Promise<string>;
  validNonce(verifier: string, jkt: string, nonce: string): Promise<boolean>;
  consumeProof(verifier: string, jkt: string, jti: string): Promise<boolean>;
  accept(identity: Identity, report: Report): Promise<Receipt>;
  list(issuer: string, tenant: string, subject: string): Promise<StoredReport[]>;
}
export interface DeviceAuthorizer { authorize(identity: Identity): Promise<void> }
export function freshness(record: StoredReport, now = Date.now()): "fresh" | "stale" {
  const observed = Date.parse(record.report.observed_at);
  const received = Date.parse(record.receipt.received_at);
  const age = now - Math.min(observed, received);
  return age >= -5000 && age <= 90_000 ? "fresh" : "stale";
}
