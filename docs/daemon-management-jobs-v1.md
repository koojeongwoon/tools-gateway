# Signed daemon jobs: LM3-1 through LM3-4

LM3-1 verifies compact Ed25519 JWS and computes a pure `managed_worker.revoke` plan.
LM3-2 adds organization-authorized issuance, atomic job/approval persistence, and DPoP delivery.
LM3-3 adds durable daemon CAS and native worker revocation/reporting. LM3-4 correlates results
and verifies the real local IAM/Gateway/native daemon path; distinct-UID OS validation also passed in a separate fixture-authority trial. Production deployment remains pending.

## Runtime setup

Requires existing `DAEMON_MANAGEMENT_ENABLED`, database, Redis and SSO configuration.
Apply normal Gateway migrations (v14 adds `daemon_management_jobs`, v15 adds `daemon_management_job_results`). IAM must have the
LM3-2 authority endpoint and optional `gateway:daemon:jobs:read` scope installed.
The configured IAM Gateway client must equal the Gateway SSO client ID.

Set `DAEMON_JOBS_SIGNING_KEY_FILE` to a provisioned Ed25519 private JWK file with exactly
`kid`, `kty: OKP`, `crv: Ed25519`, `x`, `d`. The file must be regular, not a symlink, at most
4096 bytes, owned by root or the service UID, and have no group/other access (e.g. 0600).
The runtime never generates a key automatically and never returns its private fields.
No key file means no issuance/delivery routes. Invalid configured key aborts startup.

Provision the matching public `kid` and 32-byte base64url public key to the daemon through
its trusted installation channel before consumption is enabled. This phase implements the
Gateway loader, not an automated device key-distribution system. Do not reuse IAM or device keys.
Rotate with a new `kid`, install the new daemon trust, and restart all Gateway instances using
the new key. Only the current configured kid is delivered. Old request IDs cannot be re-signed;
a new approval/request is required. Same-kid replacement and mixed-key replicas are unsupported.
Queued jobs expire after at most 300 seconds. Never log key files, tokens or DPoP proofs.

## Browser issuance

`POST /api/v1/daemon-management/jobs` accepts an authenticated `tg_session` cookie,
exact configured Gateway `Origin`, `X-Requested-With: tools-gateway` and JSON:

```json
{
  "request_id": "caller-generated-retry-id",
  "organization_id": "org-id",
  "device_id": "device-id",
  "resource": {"id": "logical-mcp-id", "version": 1, "sha256": "0000000000000000000000000000000000000000000000000000000000000000"},
  "policy_revision": 7,
  "expected_state_version": 3
}
```

This is an explicit approval of that exact resource version/hash and state expectation.
The operation is fixed to `managed_worker.revoke`; arbitrary operations, credentials, paths,
approver identities and extra fields are rejected. Resource state is not reported by LM2;
the submitted state/hash must later be verified against the daemon's protected registry.
A fresh status report is required but is not endpoint integrity proof.

The actor comes from SSO. Each issuance checks live IAM organization membership `ORG_ADMIN`,
active user/organization, Gateway service enrollment and explicit active organization entitlement.
`ORG_MANAGER`, local Gateway ADMIN, owner status, or an arbitrary boolean do not authorize this API.
IAM reads are uncached for jobs; existing report-status caching remains unchanged.
A live target-device check and fresh matching valid policy report are also required.

PostgreSQL advisory transaction locking serializes `(issuer, tenant, organization, request_id)`.
The signed payload and approval evidence (subject, role, checked time, lifecycle/service versions,
authorization ID) are stored atomically before any 202 response. Same content returns the original
job/signature; changed content or actor/binding conflicts. Expired requests are never re-signed.
A reconnect/new store instance reads the same durable record.

The browser receives only schema version, job ID, authorization ID, `status: queued`, and expiry.
`queued` is not daemon acknowledgement, successful enforcement, or process termination.

## Device delivery

`GET /api/v1/daemon-management/jobs/pending` accepts no query parameters. It requires a
Gateway-management token containing `device:identity gateway:daemon:jobs:read` and an ES256
DPoP proof bound to GET, the exact endpoint, token hash, current Gateway nonce and registered key.
Report-only tokens cannot retrieve jobs. Jobs-only tokens cannot submit reports. A newly
requested combined token may contain both scopes; IAM preserves the granted set on refresh.
Register the optional scope on `tools-daemon-management` before requesting it. Existing grants
are not automatically upgraded and ordinary service clients cannot request this reserved scope.

Each delivery rechecks current device state and the approver's current organization/service access.
Unavailable authority yields 503; revoked approval, changed versions, wrong identity/key or expired
jobs are not delivered. Response: `{schema_version: 1, jobs: [compactJws, ...]}`, maximum 20.
Delivery is repeatable, not destructive dequeue. LM3-3 must deduplicate durably and atomically
compare resource state before enforcement. Results use the existing durable reports endpoint; no separate ack endpoint is added.

## Evidence and tests

Canonical cross-repository contracts and completion records live in Agent Kit:
`docs/architecture/daemon-management-jobs-v1.md` and `docs/reconstruction/phase-lm3-2-job-issuance.md`.
Run `npm run build` and `npm test`. For real PostgreSQL tests set `DAEMON_MANAGEMENT_TEST_DATABASE`
to an isolated test database; suites create/drop their own unique schemas.
`test/daemonJobsPostgres.test.ts` verifies concurrency, restart/retry, rollback, binding and expiry.
`test/daemonJobIssuance.test.ts` covers authority, CSRF, key files and real JWS production.
`test/daemonManagement.test.ts` verifies distinct scope/method/URL and shared DPoP replay protection.
The earlier 58 signed vectors still run unchanged in Gateway and Rust.

## LM3-4 result reconciliation and read API

Migration 15 persists the latest result per issued job, referencing its device/report receipt.
Report, receipt, device head and job results commit in one transaction. Every result must match
issued job ID, canonical payload SHA256, issuer/tenant, subject/org/device/version/JKT, resource
ID and expected state version + 1. Repeated IDs or mismatches reject the entire report (409).
Old identical report retries return their original receipt without downgrading the latest result.
Results arriving after job expiry remain valid historical observations; expiry cannot prove failure
or success. Confirmed termination removes the job from pending delivery; unknown does not.

`GET /api/v1/daemon-management/jobs` uses one valid SSO session cookie and returns only that
owner's latest 100 jobs. Optional `?organization_id=...` additionally requires fresh IAM ORG_ADMIN
and matching user/service versions. Extra/malformed query parameters are rejected. Responses omit
compact signatures, JKT, key material and approval internals. State is `queued`,
`expired_unconfirmed`, `termination_unknown` or `completed`. `completed` means observed blocked
admission plus confirmed termination, not machine health. Freshness uses the older of observed and
received times with a 90s bound; stale completion remains historical and current status is unknown.

The dashboard polls owner history every 5s with no-store. Errors clear previous results; 404 hides
the opt-in panel. Org-admin history is available through the authorized API; this stage adds no org
selection UI. Only text nodes render externally supplied identifiers and names.

LM3-4: TypeScript passed; 351 tests passed including PostgreSQL management suites, four unrelated
lifecycle integration tests skipped. `test/daemonJobsPostgres.test.ts` and `test/daemonManagementUi.test.ts` cover
atomic mismatch/rollback, concurrency/retry, owner/admin boundaries and stale/unknown UI semantics.
`experiments/daemon-management/jobs-gateway.ts` is the isolated HTTPS integration fixture, not a
production launch entrypoint. Production migrations/key distribution/deployment were not performed.
