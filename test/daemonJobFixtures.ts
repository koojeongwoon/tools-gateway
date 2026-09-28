import { generateKeyPairSync } from "node:crypto";
import { JobSigner } from "../src/daemonManagement/jobs/signer.js";
import type { Authority } from "../src/daemonManagement/jobs/store.js";
import type { Identity, StoredReport } from "../src/daemonManagement/model.js";
export const config={issuer:"https://iam.invalid/t/tenant",tenant:"tenant",resource:"https://gateway.invalid/api/v1/daemon-management",client:"tools-daemon-management",readerClient:"tools-gateway-device-reader",readerSecret:"fixture-only"};
export const now=Math.floor(Date.now()/1000);
export const identity:Identity={issuer:config.issuer,tenant:config.tenant,resource:config.resource,client:config.client,
  subject:"owner",organization:"org",device:"device",version:1,jkt:"A".repeat(43),userVersion:"1",serviceVersion:"1"};
export const request={request_id:"request-1",organization_id:"org",device_id:"device",resource:{id:"mcp-test",version:1,sha256:"1".repeat(64)},policy_revision:7,expected_state_version:3};
export const actor={subject:"admin",tenantId:"tenant",email:"admin@example.invalid",userVersion:1};
export const authority:Authority={tenant_id:"tenant",subject:"admin",organization_id:"org",client_id:"gateway",role:"ORG_ADMIN",authorized:true,user_version:"1",service_access_version:"1",checked_at:now};
export const report:StoredReport={identity,report:{schema_version:1,report_id:"report",sequence:1,observed_at:new Date(now*1000).toISOString(),status:{connection:"connected",policy:{state:"valid",revision:7}}},receipt:{report_id:"report",sequence:1,received_at:new Date(now*1000).toISOString()}};
export const makeSigner=()=>JobSigner.fromJwk({...generateKeyPairSync("ed25519").privateKey.export({format:"jwk"}),kid:"fixture-key"});
