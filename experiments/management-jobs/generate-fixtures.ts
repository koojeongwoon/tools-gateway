// Generates public interoperability vectors only. Signing keys exist in memory
// for this process and are never written or printed. No operational client/key.
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { writeFileSync } from "node:fs";
import { canonicalJobJson, JOB_TYPE, JOB_AUDIENCE } from "../../src/daemonManagement/jobs/contract.js";
const keys = generateKeyPairSync("ed25519"), other = generateKeyPairSync("ed25519");
const publicJwk = keys.publicKey.export({ format: "jwk" });
const now = 1790294400;
const trust = { kid: "fixture-job-key", publicKey: publicJwk.x! };
const binding = { gateway: "https://gateway.example.invalid/api/v1/daemon-management", identityIssuer: "https://iam.example.invalid/t/tenant-fixture",
  tenant: "tenant-fixture", organization: "org-fixture", subject: "owner-fixture", device: "device-fixture", deviceVersion: 1, jkt: "A".repeat(43) };
const payload = { schema_version: 1, job_id: "job-fixture-1", iss: binding.gateway, aud: JOB_AUDIENCE,
  identity_issuer: binding.identityIssuer, tenant_id: binding.tenant, organization_id: binding.organization, subject: binding.subject,
  device_id: binding.device, device_version: binding.deviceVersion, key_jkt: binding.jkt,
  approved_by: { subject: "approver-fixture", authorization_id: "approval-fixture", approved_at: now },
  operation: "managed_worker.revoke", resource: { id: "mcp-fixture", version: 1, sha256: "1".repeat(64) }, policy_revision: 7, expected_state_version: 3, iat: now, exp: now+300 };
const current = { resource: payload.resource, policy_revision: 7, state_version: 3, status: "active" };
const header = { alg: "EdDSA", kid: trust.kid, typ: JOB_TYPE };
const hash = (s: string) => createHash("sha256").update(s).digest("hex");
function signed(body: unknown, head: unknown = header, key = keys.privateKey, raw?: string, rawHeader?: string) {
  const input = `${Buffer.from(rawHeader ?? canonicalJobJson(head)).toString("base64url")}.${Buffer.from(raw ?? canonicalJobJson(body)).toString("base64url")}`;
  return `${input}.${sign(null, Buffer.from(input), key).toString("base64url")}`;
}
const envelope = signed(payload);
const base = { compact: envelope, trust, binding, now, admission_now: now, current, prior: null as {job_id:string;digest:string}|null };
const cases: Record<string, unknown>[] = [];
function add(description: string, expected: string, changes: Partial<typeof base> = {}) {
  cases.push({ id: `J${String(cases.length+1).padStart(2,"0")}`, description, ...structuredClone(base), ...changes, expected });
}
function body(description: string, changes: object, expected = "job_invalid") { add(description, expected, { compact: signed({ ...payload, ...changes }) }); }
function h(description: string, changes: object, expected = "job_invalid") { add(description, expected, { compact: signed(payload, {...header,...changes}) }); }
add("valid signed revoke plans a state transition only", "prepare_revoke");
const tampered = envelope.split("."); const sig = Buffer.from(tampered[2]!, "base64url"); sig[0] = sig[0]! ^ 1; tampered[2] = sig.toString("base64url");
add("tampered signature", "job_signature_invalid", {compact:tampered.join(".")});
h("unknown pinned key id", {kid:"unknown"}, "job_key_untrusted");
add("different key with same kid", "job_signature_invalid", {compact:signed(payload,header,other.privateKey)});
h("algorithm substitution",{alg:"none"}); h("type confusion",{typ:"at+jwt"});
h("embedded key is forbidden",{jwk:publicJwk}); h("remote key URL forbidden",{jku:"https://other.invalid/key"}); h("critical extension forbidden",{crit:["extension"]});
body("arbitrary command field forbidden",{command:"fixture-only-command"});
body("shell operation forbidden",{operation:"shell.run"}); body("policy apply not supported in v1",{operation:"policy.apply"});
body("caller chosen file path forbidden",{path:"/fixture-only"}); body("audience array forbidden",{aud:[JOB_AUDIENCE]}); body("unknown schema version",{schema_version:2});
const withoutApproval = structuredClone(payload) as Record<string,unknown>;delete withoutApproval.approved_by;
add("missing approval reference", "job_invalid", {compact:signed(withoutApproval)});
body("empty approver",{approved_by:{...payload.approved_by,subject:""}});
body("negative device version",{device_version:-1}); body("fractional version",{device_version:1.5}); body("unsafe integer",{device_version:Number.MAX_SAFE_INTEGER+1});
body("future issue time",{iat:now+6,exp:now+306},"job_not_yet_valid"); body("expired at boundary",{exp:now},"job_invalid");
// A structurally valid but expired job is separate from a zero-length validity range.
body("expiry reached",{iat:now-1,exp:now,approved_by:{...payload.approved_by,approved_at:now-1}},"job_expired");
body("excessive lifetime",{exp:now+301}); body("approval too old",{approved_by:{...payload.approved_by,approved_at:now-301}});
body("approval after issuance",{approved_by:{...payload.approved_by,approved_at:now+1}});
for (const [field,value] of Object.entries({tenant_id:"other",organization_id:"other",subject:"other",device_id:"other",device_version:2,key_jkt:"B".repeat(43),iss:"https://other.invalid/api/v1/daemon-management",identity_issuer:"https://iam.example.invalid/t/other"})) body(`wrong ${field}`,{[field]:value},"job_binding_mismatch");
for (const [field,value] of Object.entries({id:"other",version:2,sha256:"2".repeat(64)})) add(`different installed resource ${field}`,"job_resource_mismatch",{current:{...current,resource:{...current.resource,[field]:value}}});
add("changed installed policy revision","job_stale_state",{current:{...current,policy_revision:8}});
add("competing state already advanced","job_stale_state",{current:{...current,state_version:4}});
add("already revoked resource","job_resource_revoked",{current:{...current,status:"revoked"}});
const prior = { job_id:payload.job_id,digest:hash(canonicalJobJson(payload)) };
add("same durable job record does not execute again","already_recorded",{prior,current:{...current,state_version:4,status:"revoked"}});
add("same job id with changed content","job_conflict",{prior:{...prior,digest:"2".repeat(64)}});
add("expired duplicate still rejected","job_expired",{now:now+300,admission_now:now+300,prior});
add("unknown resource state","job_state_invalid",{current:{...current,status:"unknown"}});
add("state version cannot overflow","job_state_invalid",{compact:signed({...payload,expected_state_version:Number.MAX_SAFE_INTEGER}),current:{...current,state_version:Number.MAX_SAFE_INTEGER}});
add("payload whitespace not canonical","job_invalid",{compact:signed(payload,header,keys.privateKey,JSON.stringify(payload,null,2))});
add("duplicate JSON property rejected","job_invalid",{compact:signed(payload,header,keys.privateKey,canonicalJobJson(payload).replace('{','{"job_id":"duplicate",'))});
add("duplicate JOSE header rejected","job_invalid",{compact:signed(payload,header,keys.privateKey,undefined,canonicalJobJson(header).replace('{','{"alg":"EdDSA",'))});
body("resource is a logical id not path",{resource:{...payload.resource,id:"/some/file"}});
add("bounded envelope","job_invalid",{compact:signed({...payload,extra:"x".repeat(17000)})});
add("expires between verification and admission","job_expired",{admission_now:now+300});
add("clock regressed after verification","job_clock_regressed",{admission_now:now-1});
h("private JWK field rejected",{d:"forbidden-field-not-a-key"});
add("noncanonical padded base64url","job_invalid",{compact:envelope.replace('.', '=.')});
body("null resource",{resource:null}); body("arbitrary effect field",{effect:{url:"https://other.invalid"}});
add("zero state version","job_state_invalid",{current:{...current,state_version:0}});
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const last = alphabet.indexOf(trust.publicKey.at(-1)!);
add("noncanonical pinned public key", "job_key_untrusted", {trust:{...trust,publicKey:trust.publicKey.slice(0,-1)+alphabet[last+1]}});
writeFileSync(new URL("../../test/fixtures/daemon-jobs-v1/vectors.json",import.meta.url),JSON.stringify({contract:"lynply.daemon-management-jobs",version:1,synthetic:true,notes:["Public vectors only; random signing keys discarded.","Approval references are synthetic; no organizational authorization or execution is claimed."],cases},null,2)+"\n");
console.log(`Wrote ${cases.length} public signed-job vectors; no private key persisted.`);
