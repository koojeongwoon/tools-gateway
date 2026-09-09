import { describe, it, expect } from "vitest";
import { maskPii, deepMaskPii } from "../src/policy/piiMasker.js";
import { maskSensitiveArguments } from "../src/policy/toolArgumentSanitizer.js";
import { sanitizeToolResult } from "../src/policy/toolOutputSanitizer.js";

describe("PII Masker", () => {
  it("should mask Korean Resident Registration Numbers (RRN)", () => {
    const input = "주민등록번호는 900101-1234567 입니다. 외인은 950505-5678901 입니다.";
    const result = maskPii(input);
    expect(result).toBe("주민등록번호는 900101-******* 입니다. 외인은 950505-******* 입니다.");
  });

  it("should mask mobile phone numbers", () => {
    const input = "문의사항은 010-1234-5678 또는 010 9876 5432 로 연락 바랍니다.";
    const result = maskPii(input);
    expect(result).toContain("010-****-5678");
    expect(result).toContain("010-****-5432");
  });

  it("should mask landline phone numbers", () => {
    const input = "본사 전화는 02-123-4567, 지사는 031-1234-5678 입니다.";
    const result = maskPii(input);
    expect(result).toContain("02-***-4567");
    expect(result).toContain("031-****-5678");
  });

  it("should mask email addresses", () => {
    const input = "계정 이메일: hong.gildong@example.com, 관리자: admin@service.kr, 단일자: a@test.com";
    const result = maskPii(input);
    expect(result).toContain("h***g@example.com");
    expect(result).toContain("a***n@service.kr");
    expect(result).toContain("a***@test.com");
  });

  it("should mask credit card numbers", () => {
    const input = "결제 카드번호: 1234-5678-9876-5432 (비자)";
    const result = maskPii(input);
    expect(result).toBe("결제 카드번호: 1234-****-****-5432 (비자)");
  });

  it("should deeply mask nested objects and arrays", () => {
    const userPayload = {
      name: "홍길동",
      contact: {
        phone: "010-5555-6666",
        emails: ["user@domain.com", "alt@domain.com"],
      },
      payment: {
        card: "5520-1234-5678-9012",
      },
    };

    const masked = deepMaskPii(userPayload);
    expect(masked.contact.phone).toBe("010-****-6666");
    expect(masked.contact.emails[0]).toBe("u***r@domain.com");
    expect(masked.payment.card).toBe("5520-****-****-9012");
  });

  it("should be integrated into toolOutputSanitizer", () => {
    const rawResult = {
      content: [
        {
          type: "text",
          text: "결과: 고객 연락처 010-1234-5678, 이메일 gildong@gmail.com, 카드 1111-2222-3333-4444",
        },
      ],
    };

    const sanitized = sanitizeToolResult(rawResult);
    const text = (sanitized.content as any)[0].text;
    expect(text).toContain("010-****-5678");
    expect(text).toContain("g***g@gmail.com");
    expect(text).toContain("1111-****-****-4444");
  });

  it("should be integrated into toolArgumentSanitizer (maskSensitiveArguments)", () => {
    const args = {
      target: "customer_lookup",
      query: "010-9999-8888 번호 및 test@test.com 조회",
    };

    const masked = maskSensitiveArguments(args);
    expect(masked.query).toContain("010-****-8888");
    expect(masked.query).toContain("t***t@test.com");
  });
});
