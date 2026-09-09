# IAM Tenant Endpoint 전환

## 기준 계약

- Canonical source: `/Users/jw/__dev/iam-server/TENANT_ENDPOINT_MIGRATION.md`
- Tenant: `ten_9664c024babc4110` (Lynply)
- Client ID: `cli_ab3d5bb39f894dff`
- Redirect URI: `https://tools-gateway.lynply.com/api/v1/auth/sso-callback`
- Issuer: `https://auth.snappytory.com/t/ten_9664c024babc4110`
- Discovery: `https://auth.snappytory.com/t/ten_9664c024babc4110/.well-known/openid-configuration`
- Authorization endpoint: `https://auth.snappytory.com/t/ten_9664c024babc4110/oauth2/authorize`
- Token endpoint: `https://auth.snappytory.com/t/ten_9664c024babc4110/oauth2/token`
- JWKS: `https://auth.snappytory.com/t/ten_9664c024babc4110/oauth2/jwks`

Tools Gateway는 Knowledge와 Lynply Tenant만 공유하고 Client, session, API key, Tool 권한은 독립적으로 소유한다. Client ID도 이름으로 유추해 재생성하지 않고 현재 IAM 등록과 배포 설정이 일치하는지 확인한다.

## 수정 범위

- `src/auth/oauthSession.ts`
  - authorize/token/JWKS를 Tenant 경로로 전환한다.
  - authorize 요청의 legacy `tenant` query parameter를 제거한다.
  - issuer, audience/client ID, `tenant_id == ten_9664c024babc4110`, 비어 있지 않은 `sub`를 검증한다.
- UI/security configuration
  - login/logout CSP와 signout URL이 Tenant 계약과 일치하는지 확인한다.
- 배포 ConfigMap/ExternalSecret
  - URL, issuer, tenant, client ID는 non-secret 설정으로 주입한다.
  - `tools-gateway/oauth:secret` -> `TOOLS_GATEWAY_CLIENT_SECRET` 계약을 유지하고 값을 노출하지 않는다.

IAM 로그인은 Gateway의 Tool 권한과 upstream resource/tenant 권한을 대체하지 않는다. 사용자 `tg_live_` API key는 생성 시 평문을 한 번만 반환하고 DB에 hash/prefix/scope만 저장하는 기존 경계를 유지한다.

## 완료 게이트

1. OAuth/session/management/API-key 테스트와 build가 통과한다.
2. 운영 manifest를 server-side dry-run한다.
3. ExternalSecret Ready, Pod env 주입, Argo sync/health를 확인한다.
4. 외부 login -> callback -> API key issue/list -> MCP `tools/list`/`tools/call`을 확인한다.
5. API key를 revoke한 후 동일 key의 MCP 요청이 401이 되는지 확인한다.
6. 다른 Tenant issuer/key/`tenant_id` 또는 다른 Client audience를 401로 거부한다.

IAM의 legacy endpoint는 모든 서비스 전환이 완료될 때까지 끈지 않는다.
