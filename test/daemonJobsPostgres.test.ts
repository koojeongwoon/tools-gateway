import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { Pool } from "pg";
import { randomUUID } from "node:crypto";
import { migrations } from "../src/database/migrations.js";
import { PostgresManagementStore } from "../src/daemonManagement/postgresStore.js";
import { PostgresJobStore } from "../src/daemonManagement/jobs/store.js";
import { JobService } from "../src/daemonManagement/jobs/service.js";
import { ManagementError } from "../src/daemonManagement/model.js";
import {config,identity,request,actor,authority,report,makeSigner} from "./daemonJobFixtures.js";
const url=process.env.DAEMON_MANAGEMENT_TEST_DATABASE;
describe.skipIf(!url)("management jobs real PostgreSQL",()=>{
  const schema=`jobs_${randomUUID().replaceAll("-","")}`, admin=new Pool({connectionString:url});
  let pool:Pool;
  beforeAll(async()=>{
    await admin.query(`CREATE SCHEMA ${schema}`);pool=new Pool({connectionString:url,options:`-c search_path=${schema}`});
    for(const name of ["daemon_management_reports","daemon_management_jobs","daemon_management_job_results"]) await pool.query(migrations.find(m=>m.name===name)!.sql);
  });
  beforeEach(async()=>{
    await pool.query("TRUNCATE daemon_management_jobs,daemon_management_heads CASCADE");
    await new PostgresManagementStore(pool).accept(identity,report.report);
  });
  afterAll(async()=>{await pool?.end();await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();});
  const devices={authorize:async()=>{}};
  it("serializes concurrent replicas and persists one signed job plus approval",async()=>{
    const signer=makeSigner(),sign=vi.spyOn(signer,"sign");
    const services=Array.from({length:12},()=>new JobService(config,new PostgresJobStore(pool),signer,{authority:async()=>authority},devices));
    const records=await Promise.all(services.map(s=>s.issue(actor,request)));
    expect(new Set(records.map(r=>r.compact)).size).toBe(1);expect(sign).toHaveBeenCalledTimes(1);
    const stored=await pool.query("SELECT record FROM daemon_management_jobs");expect(stored.rows).toHaveLength(1);
    expect(stored.rows[0].record.authority).toEqual(authority);
    const restarted=new JobService(config,new PostgresJobStore(pool),signer,{authority:async()=>authority},devices);
    expect((await restarted.issue(actor,request)).compact).toBe(records[0]?.compact);
    expect(await restarted.pending(identity)).toEqual([records[0]?.compact]);
    await expect(restarted.issue(actor,{...request,expected_state_version:4})).rejects.toMatchObject({code:"job_request_conflict"});
  });
  it("does not return a queued job across tenant, organization, device, owner or key rotation",async()=>{
    const signer=makeSigner(),store=new PostgresJobStore(pool),service=new JobService(config,store,signer,{authority:async()=>authority},devices);
    await service.issue(actor,request);
    for(const change of [{tenant:"other"},{organization:"other"},{device:"other"},{issuer:"https://other.invalid"}]) expect(await store.pending({...identity,...change},signer.trust.kid)).toEqual([]);
    for(const change of [{subject:"other"},{version:2},{jkt:"B".repeat(43)}]) expect(await service.pending({...identity,...change})).toEqual([]);
    expect(await store.pending(identity,"retired-key")).toEqual([]);
    expect(await store.target(config.issuer,"other","org","device")).toBeUndefined();
  });
  it("expiry prevents delivery and never re-signs the same expired request",async()=>{
    const signer=makeSigner(),service=new JobService(config,new PostgresJobStore(pool),signer,{authority:async()=>authority},devices);
    await service.issue(actor,request);await pool.query("UPDATE daemon_management_jobs SET expires_at=clock_timestamp()-interval '1 second'");
    expect(await service.pending(identity)).toEqual([]);
    await expect(service.issue(actor,request)).rejects.toMatchObject({code:"job_request_expired"});
    expect((await pool.query("SELECT count(*) FROM daemon_management_jobs")).rows[0].count).toBe("1");
  });
  it("rolls back signing failure without approval-only rows and permits retry",async()=>{
    const store=new PostgresJobStore(pool);
    await expect(store.issue(config.issuer,"tenant","org","request-1","a".repeat(64),async()=>{throw new Error("signing failed");})).rejects.toThrow("signing failed");
    expect((await pool.query("SELECT count(*) FROM daemon_management_jobs")).rows[0].count).toBe("0");
    await new JobService(config,store,makeSigner(),{authority:async()=>authority},devices).issue(actor,request);
    expect((await pool.query("SELECT count(*) FROM daemon_management_jobs")).rows[0].count).toBe("1");
  });
  it("new role/service checks can deny delivery after a durable issuance",async()=>{
    let allowed=true;
    const reader={authority:async()=>{if(!allowed)throw new ManagementError(403,"job_not_authorized");return authority;}};
    const service=new JobService(config,new PostgresJobStore(pool),makeSigner(),reader,devices);
    await service.issue(actor,request);allowed=false;
    expect(await service.pending(identity)).toEqual([]);
    await expect(service.issue(actor,request)).rejects.toMatchObject({status:403});
  });
});

describe.skipIf(!url)("job result reconciliation",()=>{
  const schema=`results_${randomUUID().replaceAll("-","")}`,admin=new Pool({connectionString:url});let pool:Pool;
  beforeAll(async()=>{await admin.query(`CREATE SCHEMA ${schema}`);pool=new Pool({connectionString:url,options:`-c search_path=${schema}`});
    for(const name of ["daemon_management_reports","daemon_management_jobs","daemon_management_job_results"])await pool.query(migrations.find(m=>m.name===name)!.sql);});
  afterAll(async()=>{await pool?.end();await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();});
  it("atomically matches identity/digest/CAS, preserves unknown, suppresses completed delivery and scopes history",async()=>{
    const reports=new PostgresManagementStore(pool),store=new PostgresJobStore(pool),signer=makeSigner();
    const reader={authority:vi.fn(async()=>authority)};
    const service=new JobService(config,store,signer,reader,{authorize:async()=>{}});
    await reports.accept(identity,report.report);const issued=await service.issue(actor,request);
    const {createHash}=await import("node:crypto"),{canonicalJobJson}=await import("../src/daemonManagement/jobs/contract.js");
    const result={job_id:issued.job.job_id,digest:createHash("sha256").update(canonicalJobJson(issued.job)).digest("hex"),resource_id:request.resource.id,state_version:request.expected_state_version+1,admission:"blocked" as const,termination:"unknown" as const};
    const next={...report.report,report_id:"result-1",sequence:2,status:{...report.report.status,job_results:[result]}};
    for(const change of [{digest:"f".repeat(64)},{resource_id:"other"},{state_version:99},{job_id:"not-a-uuid"}]) {
      await expect(reports.accept(identity,{...next,status:{...next.status,job_results:[{...result,...change}]}})).rejects.toMatchObject({code:"job_result_mismatch"});
    }
    await expect(reports.accept({...identity,version:2},next)).rejects.toMatchObject({code:"job_result_mismatch"});
    await expect(reports.accept(identity,{...next,status:{...next.status,job_results:[result,result]}})).rejects.toMatchObject({code:"job_result_mismatch"});
    expect((await reports.list(config.issuer,config.tenant,identity.subject))[0]?.report.sequence).toBe(1);
    const receipts=await Promise.all([reports.accept(identity,next),new PostgresManagementStore(pool).accept(identity,next)]);expect(receipts[0]).toEqual(receipts[1]);
    const owner={...actor,subject:identity.subject};expect((await service.list(owner))[0]?.state).toBe("termination_unknown");
    expect(await service.pending(identity)).toEqual([issued.compact]);
    const completed={...next,report_id:"result-2",sequence:3,status:{...next.status,job_results:[{...result,termination:"confirmed" as const}]}};
    await reports.accept(identity,completed);expect(await service.pending(identity)).toEqual([]);
    const restart=new JobService(config,new PostgresJobStore(pool),signer,reader,{authorize:async()=>{}});
    expect((await restart.list(owner))[0]?.state).toBe("completed");expect(await restart.list({...owner,subject:"other"})).toEqual([]);
    expect((await restart.list(actor,"org"))[0]?.state).toBe("completed");
    reader.authority.mockRejectedValue(new ManagementError(403,"job_not_authorized"));await expect(restart.list(actor,"org")).rejects.toMatchObject({status:403});
    const later=new JobService(config,store,signer,reader,{authorize:async()=>{}},()=>Math.floor(Date.now()/1000)+100);
    expect((await later.list(owner))[0]).toMatchObject({state:"completed",freshness:"stale"});
    expect(JSON.stringify(await restart.list(owner))).not.toContain(identity.jkt);
    await expect(reports.accept(identity,next)).resolves.toEqual(receipts[0]);
    expect((await restart.list(owner))[0]?.state).toBe("completed");
  });
});
