# Code Quality & Security Audit Report — tools-gateway

> **진단 일자**: 2026-09-02  
> **기술 스택**: TypeScript / Fastify / MCP Client  
> **종합 평가**: **코드 품질 94점 (A) / 종합 보안 76점 (B)**

---

## 1. ⚙️ 코드 엔지니어링 4대 관점 진단표

| 패러다임 | 점수 | 감점 | 핵심 강점 | 세부 감점 요인 및 잔여 개선점 |
| :--- | :---: | :---: | :--- | :--- |
| **DDD** | **92** | -8점 | `ToolRouteMap`, `ToolInvocationContext`, `ToolAccessPolicy` 도메인 Aggregate 구축. | **도메인 정책 팩토리 검증**: 라우트/정규식 패턴에 대한 도메인 불변식 검증 강제 보강. |
| **TDD** | **98** | -2점 | CircuitBreaker 포함 **53개 단위/통합 테스트 100% PASS**. | **카오스 엔지니어링 테스트**: MCP 프로세스 강제 종료 및 패킷 유실 시나리오 테스트 보강 여지. |
| **OOP** | **94** | -6점 | `CircuitBreaker`, `ResilientUpstreamConnection` 캡슐화 및 상태 전이 완비. | **Fastify DTO 변환 어댑터**: Request 원시 필드가 도메인 계층 인자로 직접 넘어가는 부분 분리 권장. |
| **FP** | **92** | -8점 | 불변 스냅샷 반환 및 순수 매핑 함수 파이프라인. | **Deep Freeze 누락**: `Readonly<T>` 외에 중첩 객체 런타임 `Object.freeze` 적용 부족. |

---

## 2. 🔒 보안(Security) 점수 획득 근거 & 세부 실행 과제

### ✅ 이미 구현되어 76점을 확보하고 있는 보안 장치 (코드 근거)
1. **도구 화이트리스트 (+30점)**: `src/policy/toolPolicy.ts`의 `ToolPolicy`(`default: deny`, 정규식 매칭)로 미허가 도구 원천 차단.
2. **OAuth2 Scope Guard (+26점)**: `src/auth/keyVerifier.ts` 및 `scopeGuard.ts`로 API Key 검증 및 세션 권한 바인딩.
3. **CircuitBreaker 장애 격리 (+20점)**: `src/resilience/circuitBreaker.ts`로 다운스트림 장애 폭주 차단.

### 📋 100점 달성을 위한 세부 실행 과제 목록 (-24점 감점 요인)
- **과제 1 [P1 - 도구 가드레일 / -12점]**: 도구 실행 인자(Tool Arguments) 심층 검증 (`../../../etc/passwd`, 쉘 메타문자 `;`, `&&`, `|` 차단 / `src/policy/toolArgumentSanitizer.ts`)
- **과제 2 [P1 - 일반 AppSec / -8점]**: Fastify 보안 플러그인 (`@fastify/helmet`, `@fastify/rate-limit`, `@fastify/cors`) 전면 등록
- **과제 3 [P2 - 데이터 보호 / -4점]**: 다운스트림 MCP 서버 장애 시 내부 IP/스택트레이스 유출 방지 및 `tool_usage_log` 인자 마스킹
