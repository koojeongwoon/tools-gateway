import type { FastifyInstance, FastifyReply } from "fastify";
import type { GatewaySession } from "../../auth/oauthSession.js";
import type { ManagementConfig } from "../config.js";
import { ManagementError, unavailable } from "../model.js";
import type { ManagementVerifier } from "../verifier.js";
import type { JobService } from "./service.js";
function failure(reply:FastifyReply,error:unknown) {
  const e=error instanceof ManagementError?error:unavailable();
  if(e.status===401) reply.header("www-authenticate",`DPoP error="${e.code}"`);
  if(e.nonce) reply.header("dpop-nonce",e.nonce);
  return reply.code(e.status).send({error:e.code});
}
export function registerJobRoutes(app:FastifyInstance, config:ManagementConfig, service:JobService,
  verifier:ManagementVerifier, resolveSession:(id:string)=>Promise<GatewaySession|undefined>) {
  app.post("/api/v1/daemon-management/jobs",{bodyLimit:4096},async(request,reply)=>{
    reply.header("cache-control","no-store");
    try {
      // Cookie mutation requires an exact configured origin, not request Host or forwarded headers.
      if(request.headers.origin!==new URL(config.resource).origin || request.headers["x-requested-with"]!=="tools-gateway") {
        throw new ManagementError(403,"csrf_rejected");
      }
      const cookies=request.headers.cookie?.split(";").map(s=>s.trim()).filter(s=>s.startsWith("tg_session=")) ?? [];
      if(cookies.length!==1) throw new ManagementError(401,"unauthorized");
      let id:string;
      try { id=decodeURIComponent(cookies[0]!.slice(11)); } catch { throw new ManagementError(401,"unauthorized"); }
      const session=await resolveSession(id);
      if(!session) throw new ManagementError(401,"unauthorized");
      const record=await service.issue(session,request.body);
      return reply.code(202).send({schema_version:1,job_id:record.job.job_id,
        authorization_id:record.job.approved_by.authorization_id,status:"queued",expires_at:record.job.exp});
    } catch(error) { return failure(reply,error); }
  });
  app.get("/api/v1/daemon-management/jobs",async(request,reply)=>{
    reply.header("cache-control","no-store");
    try {
      const query=request.query as Record<string,unknown>;
      if(Object.keys(query).some(k=>k!=="organization_id") || (query.organization_id!==undefined&&typeof query.organization_id!=="string")) throw new ManagementError(400,"invalid_job_request");
      const cookies=request.headers.cookie?.split(";").map(s=>s.trim()).filter(s=>s.startsWith("tg_session="))??[];
      if(cookies.length!==1) throw new ManagementError(401,"unauthorized");
      let id:string;try{id=decodeURIComponent(cookies[0]!.slice(11));}catch{throw new ManagementError(401,"unauthorized");}
      const session=await resolveSession(id);if(!session) throw new ManagementError(401,"unauthorized");
      return {schema_version:1,jobs:await service.list(session,query.organization_id as string|undefined)};
    }catch(error){return failure(reply,error);}
  });
  app.get("/api/v1/daemon-management/jobs/pending",async(request,reply)=>{
    reply.header("cache-control","no-store");
    try {
      if(Object.keys(request.query as object).length) throw new ManagementError(400,"invalid_request");
      const identity=await verifier.verify(request.headers.authorization,request.headers.dpop,"jobs");
      return {schema_version:1,jobs:await service.pending(identity)};
    } catch(error) { return failure(reply,error); }
  });
}
