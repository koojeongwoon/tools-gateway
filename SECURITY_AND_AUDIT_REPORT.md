# 🛡️ Tools Gateway 보안 감사 및 가드레일 종합 보고서

> **최종 갱신일**: 2026-09-05  
> **버전**: v0.2.0 (Security Hardened)  
> **테스트 커버리지**: 24개 테스트 파일, 100개 테스트 케이스 (100% 통과)

---

## 📌 1. 구현 완료된 보안 가드레일 요약 (Zero-Cost In-App Hardening)

추가적인 유료 인프라 비용 없이, 순수 애플리케이션 레벨(Node.js / TypeScript)에서 완비한 핵심 방어 체계입니다.

| 방어 영역 | 구현 모듈 | 방어 메커니즘 |
|---|---|---|
| **Shannon 앤트로피 비밀키 탐지** | `src/crypto/entropy.ts` | $H(X) = -\sum P(x_i)\log_2 P(x_i)$ 연산으로 Base64/암호학적 고엔트로피 난수(API 키, 토큰) 자동 검출 및 `[HIGH_ENTROPY_REDACTED]` 마스킹 |
| **공백/유니코드 난독화 우회 차단** | `src/policy/toolArgumentSanitizer.ts` | 유니코드 NFKC 정규화, 제로 너비 문자(`\u200B`, `\uFEFF` 등) 사전 제거, 다중 공백 단일화 및 `$IFS` 쉘 우회 차단 |
| **다국어 PII 보호** | `src/policy/toolArgumentSanitizer.ts` | 한국 주민등록번호(`YYMMDD-GXXXXXX`) 등 다국어 민감정보 자동 마스킹 (`950101-*******`) |
| **간접 프롬프트 주입 방어** | `src/policy/toolOutputSanitizer.ts` | 도구 응답을 `<untrusted_tool_output>` 태그로 캡슐화하고, 내부 태그 탈출(Breakout) 문자열을 중화 |
| **SSRF (사설망/클라우드 메타데이터 침투 차단)** | `src/policy/urlValidator.ts` | 커스텀 업스트림 등록 시 `127.0.0.1`, `169.254.169.254`, `10.x`, `192.168.x`, `172.16-31.x` 대역 DNS 역추적 차단 |
| **ReDoS & 페이로드 DoS 방어** | Sanitizer & OutputSanitizer | 단일 인자 문자열 길이 최대 64KB 제한 및 도구 반환 출력 2MB 초과 시 자동 트렁케이트 |
| **프로덕션 마스터 키 Fail-Fast** | `src/main.ts` | `NODE_ENV=production`에서 디폴트 키 사용 시 서버 기동 즉시 크래시 (안전하지 않은 배포 차단) |

---

## ☁️ 2. Cloudflare R2를 활용한 불변 감사 로그(WORM) 구축 방안

> **"이미 Cloudflare R2를 사용 중인데, 여기서 불변 감사 로그를 만들 수 있는가?"**  
> 👉 **결론: 100% 가능하며, 추가 비용이 사실상 0원에 가깝습니다.**

Cloudflare R2는 **AWS S3와 완벽하게 호환되는 API**를 제공하며, **송신 수수료(Egress Fee)가 $0**입니다.

### 1) R2 Object Lock (WORM: Write Once, Read Many) 활성화
- **기능**: R2 버킷 생성 시 **Object Retention(보존 잠금)** 설정을 켜면, 지정한 기간(예: 1년, 3년) 동안 관리자(Admin) 권한으로도 해당 로그 파일의 수정 및 삭제가 불가능해집니다.
- **모드**:
  - `Compliance Mode`: Cloudflare 계정 소유자나 루트 API 토큰으로도 절대 삭제 불가 (법적 규제 대응).
  - `Governance Mode`: 특정 권한을 가진 경우에만 예외적으로 조기 삭제 허용.

### 2) 권장 감사 로그 파이프라인 아키텍처

```
[MCP 도구 호출 완료]
        │
        ▼
[PostgreSQL: tool_usage_logs]  <--- 실시간 대시보드 및 통계용 (핫 스토리지)
        │
        │ (1분 또는 5분 주기 배치 집계 / 스트림)
        ▼
[Hourly GZIP/JSONL 파일 생성]  <--- '2026-09-05/11-00.jsonl.gz'
        │
        ▼ S3 PutObject API (AWS SDK v3 / S3Client)
[Cloudflare R2 (WORM Locked Bucket)]
   └── Retention: 365 Days
   └── 해시 체인(Sha256) 메타데이터 첨부
```

### 3) 구현 방식 (AWS SDK S3 호환 클라이언트)
```typescript
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

const r2 = new S3Client({
  region: "auto",
  endpoint: `https://${process.env.CF_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID!,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY!,
  },
});

// 감사 로그 업로드 시 Object Lock Retention 파라미터 적용
await r2.send(
  new PutObjectCommand({
    Bucket: "tools-gateway-audit-worm",
    Key: `logs/${year}/${month}/${day}/${hour}-audit.jsonl.gz`,
    Body: compressedLogsBuffer,
    ContentType: "application/gzip",
    ObjectLockMode: "COMPLIANCE",
    ObjectLockRetainUntilDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1년 잠금
  })
);
```

---

## 🚫 3. 외부 유료 서비스 의존으로 보류했던 항목과 무비용 대안 비교

| 보안 분류 | 유료 솔루션 (보류됨) | 비용 발생 요인 | 현재 구현된 무비용 오픈소스 대안 |
|---|---|---|---|
| **AI 인젝션/탈옥 판별** | AWS Bedrock Guardrails, Lakera AI | API 호출/토큰당 과금, 추가 Latency | `<untrusted_tool_output>` 태그 캡슐화 + 정규식 중화 |
| **KMS 암호화 키 관리** | AWS KMS, Vault Enterprise | 키 보관 월 과금 + 암/복호화 API 호출 건수당 과금 | Node.js 내장 AES-256-GCM + 프로덕션 Fail-Fast 환경변수 |
| **L7 WAF 웹방화벽** | Cloudflare Enterprise WAF, AWS WAF | 월 고정료 + 룰셋 검사 트래픽 비용 | `@fastify/helmet`, `@fastify/rate-limit`, 자체 정규식 파이프라인 |
| **ML 기반 PII 탐지** | Microsoft Presidio 컨테이너, GitGuardian | 별도 머신러닝 추론 서버 자원(RAM/CPU) 비용 | Shannon 앤트로피 수학 공식 + 한국 주민번호 정규식 매칭 |

---

## 📋 4. 후속 권장 조치 (Cloudflare R2 연동 작업 계획)

1. Cloudflare Dashboard에서 감사 로그 전용 R2 버킷 생성 (`tools-gateway-audit-worm`)
2. 버킷 설정에서 **Object Lock** 활성화 (보존 기간 90일~365일 설정)
3. `@aws-sdk/client-s3`를 설치하고, PostgreSQL 로그를 주기적으로 GZIP 파일로 압축하여 R2로 업로드하는 경량 백그라운드 태스크 연동
