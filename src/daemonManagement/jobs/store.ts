import type { Pool } from "pg";
import { createHash } from "node:crypto";
import { ManagementError, type Identity, type StoredReport } from "../model.js";
import type { ManagementJob } from "./contract.js";
export interface Authority {
  tenant_id: string; subject: string; organization_id: string; client_id: string;
  role: "ORG_ADMIN"; authorized: true; user_version: string; service_access_version: string; checked_at: number;
}
export interface StoredJob { job: ManagementJob; compact: string; kid: string; authority: Authority }
export interface ObservedJob {
  record: StoredJob;
  result: {job_id:string;digest:string;resource_id:string;state_version:number;admission:"blocked";termination:"confirmed"|"unknown"} | null;
  observed_at: string | null;
  received_at: string | null;
}
export interface JobStore {
  list(issuer:string, tenant:string, subject:string, organization?:string): Promise<ObservedJob[]>;
  target(issuer: string, tenant: string, organization: string, device: string): Promise<StoredReport | undefined>;
  issue(issuer: string, tenant: string, organization: string, requestId: string, requestHash: string,
    build: () => Promise<StoredJob>): Promise<StoredJob>;
  pending(identity: Identity, kid: string): Promise<StoredJob[]>;
}
export class PostgresJobStore implements JobStore {
  constructor(private readonly pool: Pool) {}
  async list(issuer:string, tenant:string, subject:string, organization?:string): Promise<ObservedJob[]> {
    const r=await this.pool.query(`SELECT j.record,r.result,r.observed_at,r.received_at FROM daemon_management_jobs j
      LEFT JOIN daemon_management_job_results r ON r.job_id=j.job_id
      WHERE j.issuer=$1 AND j.tenant=$2 AND (($4::text IS NULL AND j.record->'job'->>'subject'=$3) OR j.organization=$4)
      ORDER BY j.created_at DESC,j.job_id LIMIT 100`,[issuer,tenant,subject,organization??null]);
    return r.rows.map((r:{record:StoredJob;result:ObservedJob["result"];observed_at:Date|null;received_at:Date|null})=>({
      record:r.record,result:r.result,observed_at:r.observed_at?.toISOString()??null,received_at:r.received_at?.toISOString()??null}));
  }
  async target(issuer: string, tenant: string, organization: string, device: string): Promise<StoredReport | undefined> {
    const r = await this.pool.query(`SELECT identity, report, receipt FROM daemon_management_heads
      WHERE issuer=$1 AND tenant=$2 AND identity->>'organization'=$3 AND identity->>'device'=$4`,
    [issuer, tenant, organization, device]);
    return r.rows[0] as StoredReport | undefined;
  }
  async issue(issuer: string, tenant: string, organization: string, requestId: string, requestHash: string,
    build: () => Promise<StoredJob>): Promise<StoredJob> {
    const client = await this.pool.connect();
    const lock = createHash("sha256").update(JSON.stringify([issuer,tenant,organization,requestId])).digest().readBigInt64BE();
    try {
      await client.query("BEGIN");
      await client.query("SELECT pg_advisory_xact_lock($1::bigint)", [lock.toString()]);
      const prior = await client.query(`SELECT request_hash, record, expires_at > clock_timestamp() AS valid
        FROM daemon_management_jobs WHERE issuer=$1 AND tenant=$2 AND organization=$3 AND request_id=$4`, [issuer,tenant,organization,requestId]);
      if (prior.rows[0]) {
        const row = prior.rows[0] as {request_hash:string;record:StoredJob;valid:boolean};
        if (row.request_hash !== requestHash) throw new ManagementError(409,"job_request_conflict");
        if (!row.valid) throw new ManagementError(409,"job_request_expired");
        await client.query("COMMIT"); return row.record;
      }
      const record = await build();
      // The job and its approval evidence are one durable record in this transaction.
      await client.query(`INSERT INTO daemon_management_jobs
        (issuer,tenant,organization,request_id,request_hash,job_id,device_id,kid,expires_at,record)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,to_timestamp($9),$10::jsonb)`,
      [issuer,tenant,organization,requestId,requestHash,record.job.job_id,record.job.device_id,record.kid,record.job.exp,JSON.stringify(record)]);
      await client.query("COMMIT"); return record;
    } catch (error) { await client.query("ROLLBACK"); throw error; }
    finally { client.release(); }
  }
  async pending(identity: Identity, kid: string): Promise<StoredJob[]> {
    const r = await this.pool.query(`SELECT record FROM daemon_management_jobs WHERE issuer=$1 AND tenant=$2
      AND organization=$3 AND device_id=$4 AND kid=$5 AND expires_at > clock_timestamp()
      AND NOT EXISTS (SELECT 1 FROM daemon_management_job_results r WHERE r.job_id=daemon_management_jobs.job_id AND r.result->>'termination'='confirmed')
      ORDER BY created_at, job_id LIMIT 20`, [identity.issuer,identity.tenant,identity.organization,identity.device,kid]);
    return r.rows.map(row => (row as {record:StoredJob}).record);
  }
}
