# Tools Gateway

여러 upstream MCP 서버를 하나의 MCP endpoint로 통합하는 정책 기반 Tool Gateway입니다.

## Architecture boundary

```text
Oracle k3s

Agent Pods
    |
    v
Tools Gateway (ClusterIP behind authenticated Ingress)
    |
    +-- Knowledge MCP (cluster Service DNS)
    +-- Context7 MCP (external HTTPS)

Vault -> ESO -> Gateway environment -> upstream Authorization header
                   |
                   +-> PostgreSQL (service-owned DB and role)
```

- Skill과 작업 판단은 각 MCP client가 소유합니다.
- Gateway는 MCP server이면서 upstream에 대해서는 MCP client입니다.
- upstream 목록과 비민감 연결 정보는 Git에서 관리하는 YAML 파일로 선언합니다.
- Gateway는 credential을 저장하거나 발급하지 않고 기존 Vault와 ESO로 주입받은 값을 upstream 요청 헤더에만 사용합니다.
- Gateway는 Vault에 직접 접근하지 않으며 Credential Broker도 호출하지 않습니다.
- Gateway Service는 `ClusterIP`를 유지하고 `/mcp`만 인증이 강제된 Traefik Ingress로 공개합니다.
- 현재 범위는 `tools/list`와 `tools/call`입니다. prompts, resources, sampling, elicitation, tasks는 아직 중개하지 않습니다.

## Database

SaaS 데이터 계층을 활성화하면 Gateway는 기동 시 PostgreSQL 연결을 확인하고
advisory lock 아래에서 미적용 마이그레이션을 트랜잭션으로 실행합니다. 연결 또는
마이그레이션이 실패하면 요청을 받지 않고 기동에 실패합니다.

운영 자격증명은 Vault `infra/tools-gateway-db`의 `username`, `password`에 저장하고
External Secrets Operator가 `PGUSER`, `PGPASSWORD`로 주입합니다. 관리자 PostgreSQL
계정은 Gateway에 제공하지 않습니다.

- `DATABASE_ENABLED`: 운영에서는 `true`; 로컬 기본값은 `false`
- `PGHOST`, `PGPORT`, `PGDATABASE`: 비민감 연결 대상
- `PGUSER`, `PGPASSWORD`: Secret으로만 주입
- `PGPOOL_MAX`: 연결 풀 상한, 기본값 `10`
- `REDIS_HOST`, `REDIS_PORT`, `REDIS_PASSWORD`: 인증 캐시 및 `auth:events` Stream
- `API_KEY_AUTH_ENABLED`: 호출자 키 배포 전에는 `false`, 강제 인증 전환 시 `true`

첫 마이그레이션은 `users`, `user_service_permissions`, `api_keys`,
`user_mcp_upstreams`, `tool_usage_logs`와 `schema_migrations`를 생성하고
`admin@snappytory.com` 초기 관리자 행을 멱등 시딩합니다.

Redis Stream 사용자 이벤트는 `auth:events`의 `data` 필드에 아래 JSON 계약을
담습니다. 알 수 없거나 손상된 이벤트는 적용하지 않고 `auth:events:dlq`로 보냅니다.

```json
{
  "schema": "auth.user.v1",
  "eventId": "evt_...",
  "eventType": "USER_CREATED",
  "occurredAt": "2026-08-29T00:00:00Z",
  "subject": {
    "id": "auth-user-id",
    "email": "user@example.com",
    "name": "Example User"
  }
}
```

`USER_DISABLED`와 `USER_DELETED`는 사용자와 API Key를 비활성화하고 Redis 인증
캐시를 제거합니다. API Key 인증이 활성화되면 `/mcp`는 정확한 Bearer 토큰을
요구하며 `user_tool_permissions`와 키의 `tool:<pattern>` scope를 모두 만족하는
도구만 노출하고 호출합니다. 예: `knowledge.query`, `knowledge.*`.

Tool 권한은 MCP annotation의 `readOnlyHint`나 도구 이름의 동사를 해석하지 않습니다.
Gateway 권한은 “누가 어떤 Tool을 호출할 수 있는가”만 제어합니다. Tool 인자에 담긴
repository, document, tenant 등 실제 리소스 권한은 upstream MCP 서버가 최종적으로
검사해야 합니다.

## Tool names

upstream tool은 `<toolPrefix>.<tool-name>` 형식으로 외부에 노출됩니다.

```text
github.get_file
kubernetes.get_pods
```

`toolPrefix`는 Kubernetes namespace가 아닙니다. upstream 간 이름 충돌을 막고 호출 대상을 결정하는 routing key입니다.

## Upstream configuration

예시는 [config/upstreams.example.yaml](config/upstreams.example.yaml)에 있습니다.

```yaml
upstreams:
  - id: knowledge
    toolPrefix: knowledge
    networkScope: cluster
    endpoint: http://mcp-server.llm-wiki.svc.cluster.local/mcp
    transport: streamable-http
    enabled: true
    timeoutMs: 30000
    headers:
      Authorization:
        env: KNOWLEDGE_AUTHORIZATION

  - id: context7
    toolPrefix: context7
    networkScope: external
    endpoint: https://mcp.context7.com/mcp
    transport: streamable-http
    enabled: true
    timeoutMs: 30000
    headers:
      Authorization:
        env: CONTEXT7_AUTHORIZATION

toolPolicy:
  default: deny
  allow:
    - knowledge.*
    - context7.*
  deny: []
```

`deny`가 `allow`보다 우선합니다. 허용되지 않은 Tool은 `tools/list`에서 보이지 않으며, `tools/call` 실행 직전에도 같은 정책을 다시 검사합니다.

`networkScope`는 endpoint의 네트워크 경계를 명시하고 기동 전에 검증합니다.

- `cluster`: `.svc` 또는 `.svc.cluster.local`로 끝나는 Kubernetes Service hostname만 허용합니다.
- `external`: HTTPS만 허용하며 localhost, loopback, link-local, 사설 IPv4/IPv6 및 Kubernetes Service hostname을 거부합니다.

이 검증은 설정 실수와 명시적인 내부 주소 대상 SSRF를 줄이는 애플리케이션 경계입니다. DNS가 나중에 사설 IP로 해석되는 경우까지 막는 실제 네트워크 경계는 Kubernetes NetworkPolicy가 담당합니다.

`headers.<name>.env`에는 Secret 값이 아니라 환경변수 이름만 기록합니다. Gateway는 시작할 때 해당 환경변수를 읽어 upstream HTTP 요청에 헤더를 추가합니다. 참조한 환경변수가 없거나 빈 값이면 credential 없이 연결을 시도하지 않고 기동에 실패합니다.

```text
KNOWLEDGE_AUTHORIZATION=Bearer <Knowledge API key>
CONTEXT7_AUTHORIZATION=Bearer <Context7 API key>
```

실제 값은 Git이나 YAML에 넣지 않고 기존 Vault → ESO를 통해 Gateway Pod 환경변수로 주입합니다. Gateway는 헤더 값을 로그에 출력하지 않습니다.

## Kubernetes network boundary

운영 Service와 NetworkPolicy는 `__dev/k3s/namespaces/tool-gateway`에서 관리합니다. 배포 매니페스트는 다음 라벨을 계약으로 사용합니다.

- Gateway를 호출할 namespace: `tools-gateway-access: "true"`
- Gateway를 호출할 Agent Pod: `tools-gateway-client: "true"`
- upstream MCP namespace: `mcp-upstream-access: "true"`
- upstream MCP Pod: `mcp-upstream: "true"`

실제 namespace와 Pod에 라벨을 적용하고 Gateway Service는 `ClusterIP`로 유지합니다.
Traefik Pod만 Service 3000에 접근할 수 있으며 외부에는
`https://tools-gateway.lynply.com/mcp`만 노출합니다. `/healthz`와 `/readyz`는
Ingress로 공개하지 않습니다.

외부 upstream을 위해 TCP 443 egress를 허용하되 RFC1918, loopback 및 link-local CIDR은 해당 규칙에서 제외합니다. 내부 upstream은 별도의 namespace/Pod 라벨 규칙으로만 허용합니다.

## Development

Node.js 24 이상과 pnpm 11이 필요합니다.

```bash
pnpm install
cp config/upstreams.example.yaml config/upstreams.yaml
pnpm build
pnpm test
pnpm start
```

기본 endpoint:

- MCP: `POST /mcp`
- Public MCP: `POST https://tools-gateway.lynply.com/mcp` (Bearer API Key 필수)
- Liveness: `GET /healthz`
- Readiness: `GET /readyz`

환경변수:

- `UPSTREAM_CONFIG`: upstream YAML 경로, 기본값 `config/upstreams.yaml`
- `HOST`: listen address, 기본값 `0.0.0.0`
- `PORT`: listen port, 기본값 `3000`

## Current completion gate

- 공식 MCP TypeScript SDK v2 사용
- 파일 기반 upstream 검증
- upstream tool discovery와 `toolPrefix` 적용
- `networkScope` 기반 cluster/external endpoint 검증
- 환경변수 참조 기반 upstream HTTP header 주입
- header Secret 누락 시 fail closed
- `tools/call` routing
- 알 수 없는 Tool fail closed
- deny-by-default 전역 Tool allow/deny 정책
- ClusterIP 및 ingress/egress NetworkPolicy 설계 계약
- MCP in-memory end-to-end test
- API Key 인증 및 Tool 단위 권한 필터
- Cloudflare Origin TLS + Traefik `/mcp` 전용 Ingress
- 외부 무키 401, health 404, 임시 키 `tools/list` E2E

운영용 `upstreams.yaml`, ConfigMap, ExternalSecret, Deployment, Service, NetworkPolicy 및 Argo CD Application은 GitOps 저장소인 `__dev/k3s`에서 관리합니다. 이 저장소에는 설정 스키마와 로컬 개발용 예제만 둡니다.

다음 단계는 k3s 매니페스트에서 Vault에 등록된 두 값을 ESO로 Gateway Pod 환경변수에 연결한 뒤 Knowledge와 Context7에 대한 `tools/list`와 안전한 읽기 `tools/call` 실통신을 검증하는 것입니다.
