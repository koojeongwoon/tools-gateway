import { describe, expect, it, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, writeFile, chmod, symlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Fastify from "fastify";
import { JobSigner } from "../src/daemonManagement/jobs/signer.js";
import { JobService } from "../src/daemonManagement/jobs/service.js";
import { VerifiedJob } from "../src/daemonManagement/jobs/contract.js";
import type { JobStore, StoredJob } from "../src/daemonManagement/jobs/store.js";
import { ManagementError, type Identity } from "../src/daemonManagement/model.js";
import { IamDeviceReader } from "../src/daemonManagement/iamReader.js";
import { registerJobRoutes } from "../src/daemonManagement/jobs/routes.js";
import type { ManagementVerifier } from "../src/daemonManagement/verifier.js";

import {config,now,identity,request,actor,authority,report,makeSigner} from "./daemonJobFixtures.js";
function fixture() {
  let saved:StoredJob|undefined, priorHash:string|undefined;
  const store:JobStore={list:vi.fn(async()=>[]),target:vi.fn(async()=>structuredClone(report)),issue:vi.fn(async(_i,_t,_o,_id,hash,build)=>{
    if(saved) { if(hash!==priorHash) throw new ManagementError(409,"job_request_conflict");return saved; }
    const record:StoredJob=await build();saved=record;priorHash=hash;return record;
  }),pending:vi.fn(async()=>saved?[saved]:[])};
  const signer=makeSigner(), reader={authority:vi.fn(async()=>structuredClone(authority))},devices={authorize:vi.fn(async()=>{})};
  const service=new JobService(config,store,signer,reader,devices,()=>now);
  return {store,signer,reader,devices,service};
}
describe("job issuance and delivery",()=>{
  it("issues a real signed job with server-owned approval and returns the same retry",async()=>{
    const f=fixture(), a=await f.service.issue(actor,request), b=await f.service.issue(actor,request);
    expect(a).toEqual(b);expect(a.job.approved_by.subject).toBe(actor.subject);expect(a.job.subject).toBe(identity.subject);
    const verified=await VerifiedJob.verify(a.compact,f.signer.trust,{gateway:config.resource,identityIssuer:config.issuer,tenant:"tenant",organization:"org",subject:"owner",device:"device",deviceVersion:1,jkt:identity.jkt},now);
    expect(verified.plan({resource:request.resource,policy_revision:7,state_version:3,status:"active"},now).decision).toBe("prepare_revoke");
    expect(await f.service.pending(identity)).toEqual([a.compact]);
    expect(f.reader.authority).toHaveBeenCalledTimes(3);
  });
  it.each([{approved_by:{subject:"spoof"}},{command:"shell"},{tenant_id:"other"},{operation:"shell.run"}])("rejects caller-owned authority or arbitrary operation %j",async extra=>{
    const f=fixture();await expect(f.service.issue(actor,{...request,...extra})).rejects.toMatchObject({status:400});expect(f.store.issue).not.toHaveBeenCalled();
  });
  it("denies missing membership and stale session even with Gateway login",async()=>{
    const f=fixture();f.reader.authority.mockRejectedValue(new ManagementError(403,"job_not_authorized"));
    await expect(f.service.issue(actor,request)).rejects.toMatchObject({status:403});expect(f.store.target).not.toHaveBeenCalled();
    const g=fixture();await expect(g.service.issue({...actor,userVersion:2},request)).rejects.toMatchObject({status:403});
    await expect(g.service.issue({...actor,tenantId:"other"},request)).rejects.toMatchObject({status:403});
  });
  it("rejects changed request content and target identity",async()=>{
    const f=fixture();await f.service.issue(actor,request);
    await expect(f.service.issue(actor,{...request,expected_state_version:4})).rejects.toMatchObject({status:409});
    vi.mocked(f.store.target).mockResolvedValue({...report,identity:{...identity,organization:"other"}});
    await expect(f.service.issue(actor,request)).rejects.toMatchObject({status:404});
  });
  it("requires fresh valid target policy and currently authorized device",async()=>{
    const f=fixture();vi.mocked(f.store.target).mockResolvedValue({...report,report:{...report.report,observed_at:new Date((now-91)*1000).toISOString()}});
    await expect(f.service.issue(actor,request)).rejects.toMatchObject({status:409});
    const g=fixture();g.devices.authorize.mockRejectedValue(new ManagementError(403,"device_not_authorized"));
    await expect(g.service.issue(actor,request)).rejects.toMatchObject({status:403});expect(g.store.issue).not.toHaveBeenCalled();
  });
  it("rechecks approval revocation, versions, outage and device binding on delivery",async()=>{
    const f=fixture();await f.service.issue(actor,request);
    f.reader.authority.mockRejectedValueOnce(new ManagementError(403,"job_not_authorized"));expect(await f.service.pending(identity)).toEqual([]);
    f.reader.authority.mockResolvedValueOnce({...authority,service_access_version:"2"});expect(await f.service.pending(identity)).toEqual([]);
    expect(await f.service.pending({...identity,version:2})).toEqual([]);
    f.reader.authority.mockRejectedValueOnce(new ManagementError(503,"authorization_state_unavailable"));
    await expect(f.service.pending(identity)).rejects.toMatchObject({status:503});
  });
  it("retired signing kid cannot be returned by retry or delivered",async()=>{
    const f=fixture();await f.service.issue(actor,request);f.signer.trust.kid="rotated-key";
    await expect(f.service.issue(actor,request)).rejects.toMatchObject({code:"job_signing_key_retired"});
    expect(await f.service.pending(identity)).toEqual([]);
  });
  it("fails closed if durable job+approval persistence fails",async()=>{
    const f=fixture();vi.mocked(f.store.issue).mockRejectedValue(new Error("test outage"));
    await expect(f.service.issue(actor,request)).rejects.toThrow("test outage");expect(await f.service.pending(identity)).toEqual([]);
  });
});

describe("job key file",()=>{
  it("requires owner-only regular file and rejects malformed/mismatched keys",async()=>{
    const dir=await mkdtemp(join(tmpdir(),"lm32-key-"));const filename=join(dir,"key.json");
    try {
      const jwk={...generateKeyPairSync("ed25519").privateKey.export({format:"jwk"}),kid:"test"};
      await writeFile(filename,JSON.stringify(jwk),{mode:0o600});expect((await JobSigner.fromFile(filename)).trust.kid).toBe("test");
      await chmod(filename,0o644);await expect(JobSigner.fromFile(filename)).rejects.toThrow("unsafe");
      await chmod(filename,0o600);await symlink(filename,join(dir,"link"));await expect(JobSigner.fromFile(join(dir,"link"))).rejects.toThrow("unsafe");
      expect(()=>JobSigner.fromJwk({...jwk,kty:"RSA"})).toThrow();
      expect(()=>JobSigner.fromJwk({...jwk,x:generateKeyPairSync("ed25519").publicKey.export({format:"jwk"}).x})).toThrow();
    } finally {await rm(dir,{recursive:true,force:true});}
  });
});

describe("IAM authority adapter",()=>{
  it("queries every time, validates all bindings and denies outdated or forged responses",async()=>{
    let result:unknown=authority;
    const fetch=vi.fn(async(url:string)=>new Response(JSON.stringify(url.endsWith("/token")?{token_type:"Bearer",access_token:"test-only",expires_in:300}:result)));
    const reader=new IamDeviceReader(config,fetch);
    await reader.authority("admin","org","gateway");await reader.authority("admin","org","gateway");expect(fetch).toHaveBeenCalledTimes(3);
    for(const change of [{tenant_id:"other"},{subject:"other"},{organization_id:"other"},{client_id:"other"},{role:"ORG_MANAGER"},{authorized:false},{checked_at:now-60}]) {
      result={...authority,...change};await expect(reader.authority("admin","org","gateway")).rejects.toMatchObject({status:503});
    }
  });
});

describe("HTTP approval boundary",()=>{
  it("requires exact Origin and session, never returns credentials or a signed job to browser",async()=>{
    const f=fixture(),app=Fastify();const verifier={verify:vi.fn(async()=>identity)} as unknown as ManagementVerifier;
    registerJobRoutes(app,config,f.service,verifier,async id=>id==="session"?actor:undefined);
    const headers={origin:"https://gateway.invalid","x-requested-with":"tools-gateway",cookie:"tg_session=session"};
    try {
      for(const h of [{...headers,origin:"https://other.invalid"},{cookie:headers.cookie},{...headers,cookie:"tg_session=wrong"}]) {
        expect((await app.inject({method:"POST",url:"/api/v1/daemon-management/jobs",headers:h,payload:request})).statusCode).toBeGreaterThanOrEqual(400);
      }
      const response=await app.inject({method:"POST",url:"/api/v1/daemon-management/jobs",headers,payload:request});
      expect(response.statusCode).toBe(202);expect(Object.keys(response.json()).sort()).toEqual(["authorization_id","expires_at","job_id","schema_version","status"]);
      expect(response.json().status).toBe("queued");expect(response.headers["cache-control"]).toBe("no-store");
      const pending=await app.inject({method:"GET",url:"/api/v1/daemon-management/jobs/pending"});expect(pending.json().jobs).toHaveLength(1);
      expect(vi.mocked(verifier.verify)).toHaveBeenCalledWith(undefined,undefined,"jobs");
    } finally {await app.close();}
  });
});
describe("job history authorization and non-success states",()=>{
  it("keeps an unreported expired job unconfirmed and never infers execution from queue state",async()=>{
    const f=fixture(),record=await f.service.issue(actor,request);
    vi.mocked(f.store.list).mockResolvedValue([{record,result:null,observed_at:null,received_at:null}]);
    expect((await f.service.list({...actor,subject:"owner"}))[0]).toMatchObject({state:"queued",termination:"unknown"});
    const later=new JobService(config,f.store,f.signer,f.reader,f.devices,()=>record.job.exp);
    expect((await later.list({...actor,subject:"owner"}))[0]).toMatchObject({state:"expired_unconfirmed",admission:"unconfirmed",freshness:"stale"});
    await expect(f.service.list({...actor,tenantId:"other"})).rejects.toMatchObject({status:403});
    await expect(f.service.list({...actor,userVersion:2},"org")).rejects.toMatchObject({status:403});
    f.reader.authority.mockRejectedValue(new ManagementError(403,"job_not_authorized"));
    await expect(f.service.list(actor,"org")).rejects.toMatchObject({status:403});
  });
});
