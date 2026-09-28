import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import type { GatewaySession } from "../../auth/oauthSession.js";
import type { ManagementConfig } from "../config.js";
import { freshness, ManagementError, type DeviceAuthorizer, type Identity } from "../model.js";
import { canonicalJobJson, JOB_AUDIENCE, jobSchema, resourceSchema, VerifiedJob } from "./contract.js";
import type { JobSigner } from "./signer.js";
import type { Authority, JobStore, StoredJob } from "./store.js";
export const requestSchema = z.object({ request_id:jobSchema.shape.job_id,
  organization_id:jobSchema.shape.organization_id, device_id:jobSchema.shape.device_id,
  resource:resourceSchema, policy_revision:jobSchema.shape.policy_revision,
  expected_state_version:jobSchema.shape.expected_state_version }).strict();
export interface AuthorityReader { authority(subject: string, organization: string): Promise<Authority> }
const binding = (c:ManagementConfig, i:Identity) => ({gateway:c.resource,identityIssuer:c.issuer,
  tenant:i.tenant,organization:i.organization,subject:i.subject,device:i.device,deviceVersion:i.version,jkt:i.jkt});
export class JobService {
  constructor(private readonly config:ManagementConfig, private readonly store:JobStore,
    private readonly signer:JobSigner, private readonly authority:AuthorityReader,
    private readonly devices:DeviceAuthorizer, private readonly now=()=>Math.floor(Date.now()/1000)) {}
  async list(session:GatewaySession, organization?:string) {
    if(session.tenantId!==this.config.tenant) throw new ManagementError(403,"job_not_authorized");
    if(organization!==undefined) {
      if(!jobSchema.shape.organization_id.safeParse(organization).success) throw new ManagementError(400,"invalid_job_request");
      const authority=await this.authority.authority(session.subject,organization);
      if(authority.user_version!==String(session.userVersion)
        || (session.serviceAccessVersion!==undefined && authority.service_access_version!==String(session.serviceAccessVersion))) throw new ManagementError(403,"job_not_authorized");
    }
    const now=this.now();
    return (await this.store.list(this.config.issuer,this.config.tenant,session.subject,organization)).map(row=>{
      const job=row.record.job;
      // Do not expose compact signatures, registration keys, or authority internals.
      const state=row.result ? (row.result.termination==="confirmed"?"completed":"termination_unknown")
        : now>=job.exp ? "expired_unconfirmed" : "queued";
      const age=row.observed_at&&row.received_at?now*1000-Math.min(Date.parse(row.observed_at),Date.parse(row.received_at)):Infinity;
      return {job_id:job.job_id,device_id:job.device_id,organization_id:job.organization_id,
        resource:job.resource,operation:job.operation,issued_at:job.iat,expires_at:job.exp,state,
        admission:row.result?.admission??"unconfirmed",termination:row.result?.termination??"unknown",
        observed_at:row.observed_at,received_at:row.received_at,freshness:age>=-5000&&age<=90000?"fresh":"stale"};
    });
  }
  async issue(session:GatewaySession, input:unknown): Promise<StoredJob> {
    const parsed=requestSchema.safeParse(input);
    if(!parsed.success) throw new ManagementError(400,"invalid_job_request");
    const request=parsed.data;
    if(session.tenantId!==this.config.tenant) throw new ManagementError(403,"job_not_authorized");
    const authority=await this.authority.authority(session.subject,request.organization_id);
    if(authority.user_version!==String(session.userVersion)
      || (session.serviceAccessVersion!==undefined && authority.service_access_version!==String(session.serviceAccessVersion))) {
      throw new ManagementError(403,"job_not_authorized");
    }
    const target=await this.store.target(this.config.issuer,this.config.tenant,request.organization_id,request.device_id);
    if(!target || target.identity.issuer!==this.config.issuer || target.identity.tenant!==this.config.tenant
      || target.identity.organization!==request.organization_id || target.identity.device!==request.device_id) throw new ManagementError(404,"managed_device_not_found");
    await this.devices.authorize(target.identity);
    if(freshness(target,this.now()*1000)!=="fresh" || target.report.status.connection!=="connected"
      || target.report.status.policy?.state!=="valid" || target.report.status.policy.revision!==request.policy_revision) {
      throw new ManagementError(409,"managed_device_state_unavailable");
    }
    const requestHash=createHash("sha256").update(canonicalJobJson({request,subject:session.subject,identity:target.identity})).digest("hex");
    const record=await this.store.issue(this.config.issuer,this.config.tenant,request.organization_id,request.request_id,requestHash,async()=>{
      const now=this.now();
      const job=jobSchema.parse({ schema_version:1,job_id:randomUUID(),iss:this.config.resource,aud:JOB_AUDIENCE,
        identity_issuer:this.config.issuer,tenant_id:this.config.tenant,organization_id:request.organization_id,
        subject:target.identity.subject,device_id:target.identity.device,device_version:target.identity.version,key_jkt:target.identity.jkt,
        approved_by:{subject:session.subject,authorization_id:randomUUID(),approved_at:authority.checked_at},
        operation:"managed_worker.revoke",resource:request.resource,policy_revision:request.policy_revision,
        expected_state_version:request.expected_state_version,iat:now,exp:now+300 });
      const compact=this.signer.sign(job);
      await VerifiedJob.verify(compact,this.signer.trust,binding(this.config,target.identity),now);
      return {job,compact,kid:this.signer.trust.kid,authority};
    });
    if(record.kid!==this.signer.trust.kid) throw new ManagementError(409,"job_signing_key_retired");
    await VerifiedJob.verify(record.compact,this.signer.trust,binding(this.config,target.identity),this.now());
    return record;
  }
  async pending(identity:Identity): Promise<string[]> {
    await this.devices.authorize(identity);
    const records=await this.store.pending(identity,this.signer.trust.kid);
    const output:string[]=[];
    for(const record of records) {
      // Recheck current manager membership and service access on every delivery; no role cache.
      try {
        const current=await this.authority.authority(record.job.approved_by.subject,identity.organization);
        if(current.user_version!==record.authority.user_version || current.service_access_version!==record.authority.service_access_version) continue;
        await VerifiedJob.verify(record.compact,this.signer.trust,binding(this.config,identity),this.now());
        output.push(record.compact);
      } catch(error) {
        if(error instanceof ManagementError && error.status===503) throw error;
        if(error instanceof ManagementError && error.status===403) continue;
        // Invalid stored bindings, signatures and expiry are never delivered.
        if(error instanceof Error && "code" in error && String(error.code).startsWith("job_")) continue;
        throw error;
      }
    }
    return output;
  }
}
