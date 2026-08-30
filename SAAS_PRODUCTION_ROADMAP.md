# 🚀 Tools Gateway: SaaS 프로덕션 아키텍처 & 단계별 구현 로드맵

> **문서 목적**: 본 문서는 `tools-gateway`를 사내 내부 라우터 수준을 넘어 **독립적인 멀티테넌트 MCP SaaS 플랫폼**으로 고도화하기 위한 마스터 아키텍처 및 상세 구현 가이드입니다. 어떤 AI 클라이언트나 엔지니어가 보더라도 일관된 방향으로 구현을 이어갈 수 있도록 모든 스키마, 정책, 단계별 체크리스트를 완비합니다.

---

## 📌 1. 핵심 아키텍처 원칙 (Core Principles)

1. **완벽한 서비스 독립성 (Standalone Identity & Domain)**
   - 통합인증(`auth.snappytory.com`)은 **"신원 증명(Identity)"**만 제공하며, 게이트웨이 내의 유저 생명주기, 티어(Free/Pro/Enterprise), 서비스별 접근 권한은 **Tools Gateway 전용 유저 모델**에서 독자적으로 관리합니다.
2. **이벤트 기반 실시간 유저 동기화 (Redis Stream EDA)**
   - `auth-app`에서 유저 가입, 정보 수정, 탈퇴/정지 이벤트 발생 시 **Redis Stream(`redis-stream-service:6379`)**에 이벤트를 발행(`XADD`)합니다.
   - `tools-gateway`의 비동기 컨슈머 워커(`XREADGROUP`)가 이를 수신하여 동기식 HTTP 병목 없이 100% 무결합 상태로 유저 및 권한을 실시간 동기화하고, 퇴사/정지 시 발급된 모든 API Key를 즉시 무효화합니다.
3. **서비스별/도구별 세부 권한 통제 (Fine-grained RBAC & Scopes)**
   - 단순히 "전체 허용/차단"이 아닌, `Knowledge(문서검색)`, `Hermes(브라우저실행)`, `GitHub(PR생성)` 등 각 하위 서비스별로 세분화된 액션(`read`, `write`, `admin`)을 사용자별로 부여합니다.
   - 발급되는 API Key는 사용자가 가진 권한 내에서 **최소 권한의 원칙(Principle of Least Privilege)**에 따라 필요한 스코프만 선택하여 담습니다.
4. **무상태(Stateless) 고속 인증 & 다이나믹 MCP 페더레이션**
   - API Key 검증 결과와 허용 도구 메타데이터는 **Redis에 캐싱**하여 게이트웨이 병목(1ms 이하 검증)을 원천 차단합니다.
   - 요청 시점에 **"사용자가 접근 가능한 공용 도구" + "해당 사용자가 직접 등록한 개인 커스텀 MCP 도구"**를 동적으로 병합하여 응답합니다.
5. **애플리케이션 봉투 암호화 (Envelope Encryption with AES-256-GCM)**
   - Vault는 사용자의 개별 시크릿을 저장하는 DB 용도로 쓰지 않으며, **게이트웨이 파드 부팅 시 '마스터 암호화 키(Master Key)'만 1회 주입**합니다.
   - 사용자가 등록한 모든 커스텀 MCP 인증 토큰/시크릿은 **PostgreSQL(`tools_gateway_db`) 내에 AES-256-GCM으로 안전하게 암호화 보관**되어, DB 백업 하나만으로 유저 자산 전체가 100% 정합성을 유지하며 복원됩니다.

---

## 🗄️ 2. 전용 데이터베이스 스키마 (`tools_gateway_db`)

PostgreSQL 내 독립 DB `tools_gateway_db`에 생성할 5개 핵심 테이블 DDL입니다.

```sql
-- =============================================================================
-- 1. Tools Gateway 전용 유저 테이블
-- =============================================================================
CREATE TABLE users (
    id VARCHAR(64) PRIMARY KEY,                  -- tg_usr_xxxxxxxx (UUID/CUID)
    email VARCHAR(255) UNIQUE NOT NULL,          -- 사용자 이메일
    name VARCHAR(100) NOT NULL,                  -- 표시 이름
    system_role VARCHAR(20) DEFAULT 'USER',      -- 'ADMIN', 'DEVELOPER', 'USER'
    tier VARCHAR(20) DEFAULT 'FREE',             -- 'FREE', 'PRO', 'ENTERPRISE'
    external_provider VARCHAR(50),               -- 'snappytory_auth', 'github', 'local'
    external_subject_id VARCHAR(255),            -- IdP 시스템의 고유 Sub ID (매핑용)
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =============================================================================
-- 2. 유저별 서비스 권한 할당 테이블 (Fine-grained RBAC)
-- =============================================================================
CREATE TABLE user_service_permissions (
    id VARCHAR(64) PRIMARY KEY,                         -- tg_perm_xxxxxx
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service_name VARCHAR(50) NOT NULL,                  -- 'knowledge', 'context7', 'hermes', 'github'
    allowed_actions JSONB NOT NULL DEFAULT '["read"]',  -- ["read", "write", "admin"]
    granted_by VARCHAR(64),                             -- 권한 부여자
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, service_name)
);

-- =============================================================================
-- 3. 유저별 API Key 테이블 (도구 호출 인증용)
-- =============================================================================
CREATE TABLE api_keys (
    id VARCHAR(64) PRIMARY KEY,                  -- tg_key_xxxxxxxx
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,                  -- 예: "Cursor 연동용", "슬랙봇 에이전트"
    key_prefix VARCHAR(16) NOT NULL,             -- tg_live_a1b2... (식별/조회용 앞 8자리)
    key_hash VARCHAR(255) NOT NULL,              -- SHA-256 해시값 (평문 저장 절대 금지)
    allowed_scopes JSONB NOT NULL DEFAULT '["*"]',-- ["knowledge:read", "custom:notion:*"]
    rate_limit_per_minute INT DEFAULT 60,        -- 분당 호출 한도
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE,         -- 만료 일시 (NULL = 무제한)
    last_used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- =============================================================================
-- 4. 유저별 등록한 커스텀 MCP 업스트림 서버 목록 (봉투 암호화 적용)
-- =============================================================================
CREATE TABLE user_mcp_upstreams (
    id VARCHAR(64) PRIMARY KEY,                  -- tg_ups_xxxxxxxx
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tool_prefix VARCHAR(50) NOT NULL,            -- 도구 prefix (예: 'my_notion', 'erp')
    endpoint_url VARCHAR(500) NOT NULL,          -- https://my-mcp.company.com/mcp
    transport VARCHAR(20) DEFAULT 'streamable-http', -- 'streamable-http', 'sse'
    auth_type VARCHAR(20) DEFAULT 'bearer',      -- 'bearer', 'api_key', 'custom_header', 'none'
    auth_header_name VARCHAR(100) DEFAULT 'Authorization',
    encrypted_auth_value TEXT,                   -- AES-256-GCM 암호문
    encryption_iv VARCHAR(32),                   -- 초기화 벡터 (IV)
    encryption_tag VARCHAR(32),                  -- 무결성 인증 태그 (Auth Tag)
    is_enabled BOOLEAN DEFAULT TRUE,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(user_id, tool_prefix)
);

-- =============================================================================
-- 5. 도구 사용량 및 감사 로그 (사용자별 통계 및 과금 데이터)
-- =============================================================================
CREATE TABLE tool_usage_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    api_key_id VARCHAR(64) REFERENCES api_keys(id) ON DELETE SET NULL,
    tool_name VARCHAR(100) NOT NULL,             -- 'knowledge.query', 'my_notion.create_page'
    status VARCHAR(20) NOT NULL,                 -- 'SUCCESS', 'FORBIDDEN', 'ERROR'
    status_code INT NOT NULL,                    -- 200, 403, 500 등
    duration_ms INT NOT NULL,                    -- 응답 지연시간(ms)
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 인덱스 최적화
CREATE INDEX idx_api_keys_lookup ON api_keys(key_prefix, is_active);
CREATE INDEX idx_user_perms ON user_service_permissions(user_id);
CREATE INDEX idx_usage_logs_user ON tool_usage_logs(user_id, created_at DESC);
```

---

## 🔄 3. 통합인증 & 런타임 요청 처리 흐름도

```
[ auth.snappytory.com (auth-app) ]
              │
              ▼ (사용자 생성/수정/삭제 이벤트: XADD auth:events)
┌────────────────────────────────────────────────────────────────────────┐
│ Redis Stream (`redis-stream-service:6379`)                             │
│ ➔ Topic: `auth:events` / Group: `tools-gateway-sync`                   │
└──────────────────────────────┬─────────────────────────────────────────┘
                               │
                               ▼ (실시간 비동기 소비: XREADGROUP)
┌────────────────────────────────────────────────────────────────────────┐
│ Tools Gateway Background Worker                                        │
│ - `USER_CREATED`  ➔ `users` 테이블에 자동 프로비저닝 + 기본 권한 부여   │
│ - `USER_DISABLED` ➔ `users.is_active=F` + API Key 및 Redis 캐시 전량삭제│
└────────────────────────────────────────────────────────────────────────┘

==========================================================================

[ AI Client (Cursor / Hermes / Agent) ]
              │
              ▼  POST /mcp (Header: Authorization: Bearer tg_live_secret123...)
┌────────────────────────────────────────────────────────────────────────┐
│ Fastify Tools Gateway Request Pipeline                                 │
│                                                                        │
│ 1. [Auth Guard]:                                                       │
│    - 토큰에서 prefix 추출 (tg_live_xxxx)                               │
│    - Redis 캐시 확인 ➔ 없으면 DB `api_keys` 해시 일치 검증            │
│    - 검증 성공 시 `req.user` 및 `req.apiKey` 컨텍스트 주입             │
│                                                                        │
│ 2. [Rate Limiter]:                                                     │
│    - Redis Token Bucket: `rate_limit:user:{userId}` 확인 및 차감        │
│                                                                        │
│ 3. [Scope & Permission Guard]:                                         │
│    - CASE A (`tools/list`):                                            │
│      공용 도구 중 허가된 것 + 유저의 커스텀 MCP 도구 목록만 병합 반환  │
│    - CASE B (`tools/call`):                                            │
│      요청된 도구의 Scope 권한 검사 (미보유 시 즉시 403 / -32003 에러)   │
│                                                                        │
│ 4. [Proxy & Header Injection]:                                         │
│    - 공용 도구 ➔ 글로벌 공용 헤더 + `X-Consumer-Id: {userId}` 주입      │
│    - 커스텀 도구 ➔ DB에서 암호화된 토큰 로드 후 마스터 키로 즉시      │
│      메모리 내 복호화(AES-GCM) ➔ 대상 MCP 서버로 안전하게 프록시 전송  │
│                                                                        │
│ 5. [Audit Logger]:                                                     │
│    - 비동기로 `tool_usage_logs`에 실행 결과, 시간, 상태 기록           │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📅 4. 단계별 구현 로드맵 (Actionable Phases)

```
[Phase 1: DB & 모델] ➔ [Phase 2: Redis Stream & 인증 가드] ➔ [Phase 3: 관리 REST API] ➔ [Phase 4: 커스텀 MCP & 암호화] ➔ [Phase 5: 웹 콘솔 UI]
```

### 🔹 Phase 1: 전용 DB 프로비저닝 및 기본 데이터 계층 구축
- **상태 (2026-08-29)**: 완료 (운영 클러스터 검증 포함)
- **목표**: PostgreSQL에 `tools_gateway_db` 생성 및 ORM/DB 드라이버 연동
- **세부 작업**:
  1. [x] PostgreSQL `tools_gateway_db` 생성 및 `tools_gateway_user` 계정 생성/권한 부여
  2. [x] 위 5개 핵심 테이블 DDL을 버전 마이그레이션으로 구현
  3. [x] `pg` 연결 풀 및 fail-closed 기동 구성
  4. [x] 초기 관리자 유저(`admin@snappytory.com`) 멱등 시딩
  5. [x] Vault `infra/tools-gateway-db` → ExternalSecret → Pod 환경변수 연결
  6. [x] 운영 롤아웃 및 실제 테이블/관리자 시드 검증

### 🔹 Phase 2: Redis Stream 유저 동기화 & Gateway API Key 가드
- **상태 (2026-08-29)**: 진행 중 (호환 배포 후 API Key 배포/강제 전환 대기)
- **목표**: Redis Stream 이벤트 컨슈머 탑재 및 키 기반 인증으로 게이트웨이 보안 잠금
- **세부 작업**:
  1. [x] `src/events/userSyncConsumer.ts`: Redis Stream `auth:events` 구독 워커 구현
  2. [x] `src/auth/keyVerifier.ts`: SHA-256 해시 검증 및 Redis 캐싱 레이어 구현
  3. [x] `src/auth/scopeGuard.ts`: `tools/call` 실행 전 스코프 일치 검증 로직
  4. [x] `tools/list` 요청 시 유저 권한에 맞는 도구만 동적 반환
  5. [x] 인증/스코프 단위 테스트
  6. [ ] 관리자 API Key 1회 발급 및 호출자 Secret 배포
  7. [x] `API_KEY_AUTH_ENABLED=true` 전환 후 무키 401/임시 유효 키 운영 E2E
  8. [ ] auth-app `auth.user.v1` publisher 연동 E2E
  9. [x] annotation 비의존 Tool 단위 권한(`user_tool_permissions`) 적용

### 🔹 Phase 3: 유저 & API Key 관리 REST API 엔드포인트
- **상태 (2026-08-29)**: 코드 구현 및 로컬 검증 완료, 운영 SSO client/Vault 연결과 배포 대기
- **목표**: 사용자가 API 키를 발급/조회/삭제하고 자신의 권한을 확인할 수 있는 백엔드 API
- **세부 작업**:
  1. [x] `GET /api/v1/auth/login` + `GET /api/v1/auth/sso-callback`: Authorization Code + PKCE 로그인, Gateway 서버 세션, JIT 유저 프로비저닝
  2. [x] `POST /api/v1/keys`: 새 API Key 발급 (원문 1회 반환 + DB SHA-256 해시 저장)
  3. [x] `GET /api/v1/keys`: 내가 발급한 키 목록 조회 (Prefix, 생성일, 최근사용일)
  4. [x] `DELETE /api/v1/keys/:keyId`: 소유자 범위 API Key 즉시 soft revoke 및 인증 캐시 무효화
  5. [x] `GET /api/v1/permissions`: 현재 유저가 사용 가능한 서비스/도구 권한 목록 조회
  6. [x] Tool 선택 UI 제외; 키 스코프는 발급 시점의 `user_tool_permissions`에서 서버가 생성
  7. [x] auth-app에 SUPER_ADMIN 전용 `POST /api/admin/clients` 구현 (PKCE public client, client secret/Vault 불필요)
     - 운영에서 독립 tenant `tools-gateway` 생성 후 동일 이름의 client를 해당 tenant에만 매핑
  8. [ ] 운영 배포 후 login → callback → key 생성/목록/폐기 → 폐기 키 401 E2E

### 🔹 Phase 4: 유저 커스텀 MCP 등록 & AES-GCM 봉투 암호화
- **상태 (2026-08-30)**: 완료 (운영 배포 및 Vault 연동 검증 완료)
- **목표**: 사용자가 개인 MCP 서버 URL과 토큰을 등록하고 게이트웨이에서 통합 관리
- **세부 작업**:
  1. [x] `src/crypto/envelopeCrypto.ts`: AES-256-GCM 기반 봉투 암복호화 유틸리티 구현 및 단위 테스트
  2. [x] `src/api/customUpstreamService.ts`: DB `user_mcp_upstreams` 연동 및 토큰 암호화 저장/복호화
  3. [x] `POST /api/v1/upstreams`, `GET /api/v1/upstreams`, `DELETE /api/v1/upstreams/:id` 엔드포인트 구현
  4. [x] Vault `secret/tools-gateway/crypto` -> `ENCRYPTION_MASTER_KEY` ExternalSecret 연동 및 롤아웃

### 🔹 Phase 5: 웹 관리 콘솔 (UI) & 프로덕션 배포
- **상태 (2026-08-30)**: 완료 (운영 배포 완료)
- **목표**: 개발자/사용자가 브라우저에서 편리하게 관리할 수 있는 웹 대시보드
- **세부 작업**:
  1. [x] 대시보드 UI (`src/ui/dashboardHtml.ts`): API Key 생성/폐기, 커스텀 MCP 등록 모달, Cursor/Claude 설정 JSON 원클릭 복사
  2. [x] 비로그인 시 SSO 자동 리다이렉트 (`/` -> `auth.snappytory.com` -> `/`)
  3. [x] Traefik Ingress 및 공개 도메인 (`tools-gateway.lynply.com`) 연동
  4. [x] Rate Limit 및 DoS 방어 정책 적용

### 🔹 Phase 6: 🛡️ 보안 로컬 에이전트 CLI (`tg-local`)
- **목표**: 개인 PC 샌드박싱(안전한 파일 조작/쉘 실행) + 게이트웨이 원격 도구 하이브리드 연동
- **세부 작업**:
  1. 경량 CLI (`tg-local`): 워크스페이스 샌드박스 파일시스템 도구 내장 (`.ssh`, `.env`, `.pem` 등 유출 차단)
  2. 쉘 명령어 화이트리스트/블랙리스트 차단 가드
  3. 대시보드에서 `curl -sSL https://tools-gateway.lynply.com/install.sh | bash` 원클릭 설치 스크립트 제공
  4. `tg-local setup-cursor` 등 AI 클라이언트 config.json 자동 주입 명령 제공

### 🔹 Phase 7: 🧠 지능형 분산 도구 라우팅 & 오케스트레이션 MSA (Spring Cloud / Spring AI 기반)
- **목표**: 대규모 엔터프라이즈 환경에서 수십~수백 개의 MCP 도구를 지능적으로 라우팅하고, 앞단(Edge Ingress)과 뒷단(Tool Execution Workers)을 MSA로 분리하여 독립 스케일링(HPA) 및 장애 격리(Fault Tolerance) 달성
- **아키텍처 스택**:
  - **Tier 1 (Edge Ingress Gateway)**: Spring Cloud Gateway / Fastify (인증, 토큰 캐싱, Rate Limiting, 트래픽 라우팅)
  - **Tier 2 (Semantic Orchestrator & Router)**: Spring Boot / Spring AI (임베딩 유사도 검색, 문맥 기반 Top-K 도구 동적 선별, Fan-out/Fan-in 병렬 실행)
  - **Tier 3 (MCP Client Execution Pool)**: Java 21 가상 스레드(Virtual Threads) 기반 하위 MCP 풀링, 서킷 브레이커(Resilience4j), 타임아웃 격리
- **세부 작업**:
  1. **MSA 분리 & 독립 스케일링 모델 설계**:
     - 가벼운 I/O 인그레스 게이트웨이와 무거운 임베딩/오케스트레이션 워커를 별도 Pod/서비스로 분리
     - 도구 호출 트래픽 폭증 시 실행 워커(Worker) Pod만 수평 자동 확장(HPA)
  2. **Tool Embedding & Indexing**: 
     - 모든 등록된 도구(사내 공용 + 유저 커스텀)의 이름과 설명을 벡터 임베딩하여 pgvector 또는 Qdrant/인메모리 색인
  3. **Context-Aware Dynamic Filtering (Dynamic `tools/list`)**:
     - 클라이언트 문맥에 맞춰 전체 100개 중 가장 적합한 Top-K(예: 3~5개) 도구만 선별하여 AI 클라이언트에 전달 (Context Overflow 방지)
  4. **단일 진입점 메타 도구 (`tools_gateway.dispatch`) 지원**:
     - AI 클라이언트에는 단 하나의 오케스트레이터 도구만 노출하고, 게이트웨이 내부 엔진이 적절한 하위 MCP들을 직접 호출 및 결과 취합
  5. **엔터프라이즈 회복탄력성 (Resilience4j)**:
     - 하위 특정 MCP 서버 장애 시 게이트웨이 전체 전파 방지 (서킷 브레이커, Fallback, 지수 백오프 재시도)

---

## 🎯 5. 다음 작업 가이드 (AI Agent Execution Checklist)

다른 AI 에이전트나 작업자가 이어서 작업을 진행할 때는 아래 순서대로 실행합니다:

1. **[Phase 1 착수]**: PostgreSQL에 `tools_gateway_db` 데이터베이스 및 전용 사용자를 생성하고 위 DDL을 적용합니다.
2. **[코드베이스 반영]**: `src/config/database.ts`를 생성하여 DB 커넥션 풀을 연결합니다.
3. **[Redis Stream 구독기 탑재]**: `src/events/user-sync-consumer.ts`를 작성하여 `auth:events`를 수신하도록 등록합니다.
4. **[API Key 생성 스크립트 작성]**: 시스템 관리자가 첫 번째 관리자용 API Key를 발급할 수 있는 CLI/스크립트를 구성합니다.
