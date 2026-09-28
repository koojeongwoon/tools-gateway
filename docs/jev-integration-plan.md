# Tools Gateway: Jev 연동 구현 계획서 (Implementation Plan)

## 1. 목표
Tools Gateway의 요청 처리 파이프라인에 Jev(TypeSafe System One)를 단계적으로 도입하여, 초고속 보안 가드레일 판정 및 지능형 가상 도구 라우팅 기능을 구축한다.

---

## 2. 단계별 마일스톤 (Phased Roadmap)

### Phase 1: Jev 클라이언트 인프라 및 환경 설정 구축
- [x] **Jev 설정 스키마 정의**:
  - `JevConfig` (`apiKey`, `endpoint`, `timeoutMs`, `enabled`, `cacheTtlSeconds`).
  - 환경변수 및 Config 로더 연동 (`JEV_API_KEY`, `JEV_ENDPOINT`, `JEV_CACHE_TTL_SECONDS`).
- [x] **TypeSafe / Jev TypeScript 클라이언트 모듈 구현 (`src/jev/jevClient.ts`)**:
  - 단일 병렬 결정 질의(State + Questions) 전송 및 파싱.
  - 타임아웃 처리(기본 500ms / 80~100ms 가변) 및 실패 시 안전 패스스루(Fail-safe).
- [x] **결정 결과 Redis 캐싱 (`src/jev/jevDecisionCache.ts`)**:
  - 동일한 입력 파라미터/상태에 대한 결정 결과를 SHA-256 해시 키로 단기 캐싱(기본 300초)하여 레이턴시 최소화.

### Phase 2: 지능형 보안 가드레일 (AI Policy Guardrail) 적용
- [x] **가드레일 질문 스키마 설계**:
  - 인젝션/시스템 파괴/데이터 유출 위험 여부 확률 (`is_malicious: noul`)
- [x] **`createGatewayServer` 파이프라인 연동 (`src/policy/jevGuardrail.ts`)**:
  - 도구 실행 직전 Jev 가드레일 판정 인터셉터 연동.
  - 임계값 초과 시 403 Forbidden 차단 및 Fail-open 폴백 지원.
- [x] **단위 및 통합 테스트 작성 (`test/jevGuardrail.test.ts`)**:
  - 정상 요청 패스스루, 악성 인자 차단, 타임아웃/오류 시 Fail-open/Fail-closed, Redis 캐시 동작 검증 완료.

### Phase 3: 가상 메타 도구 라우팅 (Virtual Tool Dispatcher) PoC
- [x] **통합 라우터 도구 등록 (`gateway.smart_dispatch`)**:
  - 호출 가능한 하위 도구 카탈로그(Allowed Tools) 정보를 Jev Decision State 및 Choice Criteria로 자동 변환.
  - 사용자 자연어 인텐트(`intent`)에 맞는 최적의 업스트림 도구를 Jev가 초고속 선택 (`selected_tool: choice`).
- [x] **`createGatewayServer` 및 `ToolRouteMap` 동적 디스패치 연동**:
  - Jev가 선택한 대상 도구에 대해 파라미터 유효성 및 접근 정책 재검증 후 실제 업스트림 도구로 투명 디스패치.
- [x] **단위 및 E2E 테스트 작성 (`test/jevVirtualRouter.test.ts`)**:
  - 단일 후보 자동 라우팅, 다중 후보 Jev 기반 스마트 라우팅, Jev 장애 시 Graceful Fallback, MCP Client E2E 호출 검증 완료.

---

## 3. 리스크 및 완화 대책 (Risk & Mitigation)

| 위험 요소 | 영향도 | 완화 대책 |
| :--- | :--- | :--- |
| **외부 API 레이턴시 지연** | P99 응답 시간 증가 | 80ms Strict 타임아웃 적용 + 타임아웃 시 기존 정적 룰로 즉시 Fallback |
| **Jev 서비스 일시 장애** | 도구 호출 불가 위험 | 서킷 브레이커 적용 및 장애 시 비활성화(Bypass) 모드 전환 |
| **오탐(False Positive) 차단** | 정상 사용자 요청 거절 | 임계값(Probability Threshold) 보수적 설정(예: 확신도 > 0.85) 및 감사 로그 수집 후 튜닝 |

---

## 4. 일정 및 산출물
- **산출물**:
  - `docs/jev-routing-investigation.md` (조사 보고서)
  - `docs/jev-integration-plan.md` (본 계획서)
  - `src/jev/*` (클라이언트 및 가드레일 모듈)
  - 관련 Vitest 테스트 스위트
