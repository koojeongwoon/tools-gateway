import { createHash, randomBytes } from "node:crypto";
import { canonicalJobJson } from "./jobs/contract.js";
import type { StoredJob } from "./jobs/store.js";
import type { Pool } from "pg";
import { ManagementError, type Identity, type ManagementStore, type Receipt, type Report, type StoredReport } from "./model.js";
const digest = (values: unknown[]) => createHash("sha256").update(JSON.stringify(values)).digest("hex");
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(",")}}`;
  return JSON.stringify(value);
}
export class PostgresManagementStore implements ManagementStore {
  constructor(private readonly pool: Pool) {}
  async issueNonce(verifier: string, jkt: string): Promise<string> {
    const nonce = randomBytes(32).toString("base64url");
    await this.pool.query("DELETE FROM daemon_management_nonces WHERE expires_at <= clock_timestamp()");
    await this.pool.query("INSERT INTO daemon_management_nonces (key, expires_at) VALUES ($1, clock_timestamp() + interval '60 seconds')", [digest([verifier, jkt, nonce])]);
    return nonce;
  }
  async validNonce(verifier: string, jkt: string, nonce: string): Promise<boolean> {
    const r = await this.pool.query("SELECT 1 FROM daemon_management_nonces WHERE key=$1 AND expires_at > clock_timestamp()", [digest([verifier, jkt, nonce])]);
    return r.rowCount === 1;
  }
  async consumeProof(verifier: string, jkt: string, jti: string): Promise<boolean> {
    const r = await this.pool.query(`INSERT INTO daemon_management_proofs (key, expires_at)
      VALUES ($1, clock_timestamp() + interval '120 seconds') ON CONFLICT (key) DO UPDATE
      SET expires_at=EXCLUDED.expires_at WHERE daemon_management_proofs.expires_at <= clock_timestamp() RETURNING key`, [digest([verifier, jkt, jti])]);
    // Cleanup is indexed and replay insertion above is atomic across replicas.
    await this.pool.query("DELETE FROM daemon_management_proofs WHERE expires_at <= clock_timestamp()");
    return r.rowCount === 1;
  }
  async accept(identity: Identity, report: Report): Promise<Receipt> {
    const key = digest([identity.issuer, identity.tenant, identity.device]);
    const payloadHash = createHash("sha256").update(canonical(report)).digest("hex");
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("INSERT INTO daemon_management_heads (key, issuer, tenant, subject, sequence) VALUES ($1,$2,$3,$4,0) ON CONFLICT DO NOTHING",
        [key, identity.issuer, identity.tenant, identity.subject]);
      const head = (await client.query("SELECT subject, sequence FROM daemon_management_heads WHERE key=$1 FOR UPDATE", [key])).rows[0] as {subject: string; sequence: string};
      if (head.subject !== identity.subject) throw new ManagementError(403, "device_not_authorized");
      const duplicates = await client.query("SELECT report_id, sequence, payload_hash, receipt FROM daemon_management_reports WHERE device_key=$1 AND (report_id=$2 OR sequence=$3)", [key, report.report_id, report.sequence]);
      if (duplicates.rows.length) {
        const prior = duplicates.rows[0] as { report_id: string; sequence: string; payload_hash: string; receipt: Receipt };
        if (duplicates.rows.length !== 1 || prior.report_id !== report.report_id || Number(prior.sequence) !== report.sequence || prior.payload_hash !== payloadHash) throw new ManagementError(409, "report_conflict");
        await client.query("COMMIT"); return prior.receipt;
      }
      if (report.sequence <= Number(head.sequence)) throw new ManagementError(409, "report_out_of_order");
      const receipt: Receipt = { report_id: report.report_id, sequence: report.sequence,
        received_at: (await client.query("SELECT clock_timestamp() AS time")).rows[0].time.toISOString() as string };
      await client.query("INSERT INTO daemon_management_reports (device_key, report_id, sequence, payload_hash, receipt) VALUES ($1,$2,$3,$4,$5)", [key, report.report_id, report.sequence, payloadHash, receipt]);
      const seen = new Set<string>();
      for (const result of report.status.job_results ?? []) {
        if (seen.has(result.job_id)) throw new ManagementError(409, "job_result_mismatch");
        seen.add(result.job_id);
        // Text comparison safely rejects non-UUID IDs without a database cast exception.
        const issued = await client.query("SELECT record FROM daemon_management_jobs WHERE job_id::text=$1 AND issuer=$2 AND tenant=$3", [result.job_id, identity.issuer, identity.tenant]);
        const job = (issued.rows[0] as {record:StoredJob}|undefined)?.record.job;
        if (!job || job.iss !== identity.resource || job.subject !== identity.subject
          || job.organization_id !== identity.organization || job.device_id !== identity.device
          || job.device_version !== identity.version || job.key_jkt !== identity.jkt
          || job.resource.id !== result.resource_id || job.expected_state_version + 1 !== result.state_version
          || createHash("sha256").update(canonicalJobJson(job)).digest("hex") !== result.digest
          || Date.parse(report.observed_at) < job.iat * 1000 - 5000) {
          throw new ManagementError(409, "job_result_mismatch");
        }
        // Same transaction as the report/receipt. Retry cannot commit twice or lose the evidence.
        await client.query(`INSERT INTO daemon_management_job_results
          (job_id,device_key,report_id,sequence,result,observed_at,received_at) VALUES ($1,$2,$3,$4,$5,$6,$7)
          ON CONFLICT (job_id) DO UPDATE SET report_id=EXCLUDED.report_id,sequence=EXCLUDED.sequence,
            result=EXCLUDED.result,observed_at=EXCLUDED.observed_at,received_at=EXCLUDED.received_at
          WHERE daemon_management_job_results.device_key=EXCLUDED.device_key AND daemon_management_job_results.sequence<EXCLUDED.sequence`,
          [result.job_id,key,report.report_id,report.sequence,result,report.observed_at,receipt.received_at]);
      }
      await client.query("UPDATE daemon_management_heads SET sequence=$2, identity=$3, report=$4, receipt=$5 WHERE key=$1", [key, report.sequence, identity, report, receipt]);
      await client.query("COMMIT"); return receipt;
    } catch (error) { await client.query("ROLLBACK"); throw error; }
    finally { client.release(); }
  }
  async list(issuer: string, tenant: string, subject: string): Promise<StoredReport[]> {
    const r = await this.pool.query("SELECT identity, report, receipt FROM daemon_management_heads WHERE issuer=$1 AND tenant=$2 AND subject=$3 AND sequence>0 ORDER BY key LIMIT 100", [issuer, tenant, subject]);
    return r.rows as StoredReport[];
  }
}
