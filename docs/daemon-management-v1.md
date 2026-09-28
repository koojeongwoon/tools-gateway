# Daemon management v1 (LM2-4)

The optional management channel is separate from `/mcp`. IAM owns registered
keys and revocation; the Gateway owns received reports. This does not establish
whole-device integrity or bind a client's direct MCP calls to a device.

## Configuration

Use the existing database/Redis/SSO settings, then configure:

- `DAEMON_MANAGEMENT_ENABLED=true`: enables this deployment's routes. This is
  not an IAM client flag or a bypass of required scopes/claims.
- `DAEMON_MANAGEMENT_RESOURCE=https://<gateway>/api/v1/daemon-management`:
  exact public HTTPS resource, including when TLS terminates at a proxy.
- `DAEMON_DEVICE_READER_SECRET`: injected secret for the tenant's confidential
  `tools-gateway-device-reader` client. Never place it in client configuration.
- Existing `AUTH_SERVER_URL`, `TOOLS_GATEWAY_TENANT_ID` select the pinned issuer.

IAM must register the `tools-daemon-management` public client and the restricted
reader client for this resource. Both daemon and Gateway service entitlements
are required by IAM. Existing service enforcement settings are unchanged.
Migration 13 adds only management tables. HTTPS ingress must preserve Authorization
and DPoP headers. Untrusted Host/Forwarded values never determine the proof target.

## Requests and display

`POST /api/v1/daemon-management/reports` requires the management RS256 access
token with DPoP ES256, the registered P-256 key, resource, device identity and
`device:identity gateway:daemon:report`. Gateway issues its own 60-second nonce;
proof IDs are atomically consumed for 120 seconds in PostgreSQL. Database or IAM
failure closes authorization. Successful IAM state is cached at most 15 seconds
from lookup start using the monotonic clock, including network time.

Reports are bounded to 16 KiB. `model.ts` defines the strict v1 schema: report ID,
durable sequence, RFC3339 observation, local connection, optional version/policy/
execution and up to 20 closed event kinds with numeric metadata. No paths,
free-form reasons, tool arguments, raw file contents or credentials are accepted.
The same ID/sequence/content returns its original 202 receipt after authentication
is checked again. Altered duplicates and unknown lower sequences return 409.
A newer sequence is required to change latest state. Device identity is taken
only from the verified token and IAM lookup, never from the report body.

`GET /api/v1/daemon-management/devices` uses the existing SSO session and returns
only that tenant/subject's latest reports (v1 limit: 100). There is no implied
organization-admin list permission. The dashboard displays IAM authorization
separately from freshness, policy and execution. Freshness expires after 90
seconds using the older of observation and receipt. It refreshes every five
seconds and replaces old display values on request failure. A stale or accepted
report never grants execution permission. Registration without a first report
will not appear; IAM's reader API deliberately has no listing permission.

The outbox is durable on the daemon. Gateway retains receipt hashes to detect
old duplicates; archive/retention and fleet-scale capacity remain operational
work before a production pilot. Issued nonces/proofs are expired and pruned.

## Validation and limits

`test/daemonManagement*.test.ts` covers the public shared fixture, M01–M30,
cache/version failures, owner isolation, UI rendering and database races.
Run PostgreSQL checks against a disposable database using
`DAEMON_MANAGEMENT_TEST_DATABASE`; each run creates/drops its own schema.
`tsconfig.daemon-management.json` provides a focused type check. It does not
replace the normal repository build.

`experiments/daemon-management/gateway.ts` is a localhost-only integration
fixture used by the daemon's `experiments/management-report/`. It uses real
Gateway routes, JWKS, IAM reader, PostgreSQL and Redis session resolution.
Dashboard sessions are seeded synthetic records; this is not a new browser SSO
or customer IdP test. It is never a production entry point.

2026-09-25 local interoperability passed: real enrollment/token issuance, native
worker policy/event report, lost-receipt retry, process restart, 90-second stale
status and revoke rejection after the 15-second cache window. Full test suite:
259 passed, 4 preexisting optional tests skipped. Focused type check passes.
The initial LM2-4 baseline had 10 JEV TypeScript diagnostics. A subsequent
2026-09-25 type-only repair resolved them with strict compiler settings preserved.
The full build now passes; regression tests pass 263 with 8 environment-dependent
integration tests skipped on that run. No deployment, commit or push performed.
