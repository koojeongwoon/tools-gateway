import { describe, it, expect } from "vitest";
import {
  ToolArgumentSanitizer,
  SanitizationViolationError,
  normalizeUnicodeAndWhitespace,
  maskSensitiveArguments,
} from "../src/policy/toolArgumentSanitizer.js";

describe("Unicode, Whitespace & Evasion Attack Sanitization", () => {
  const sanitizer = new ToolArgumentSanitizer({ strict: true });

  describe("normalizeUnicodeAndWhitespace", () => {
    it("should strip zero-width characters (ZWSP, ZWNJ, ZWJ, BOM)", () => {
      // "c\u200Burl" -> "curl"
      const withZwsp = "c\u200Bu\u200Crl\uFEFF";
      expect(normalizeUnicodeAndWhitespace(withZwsp)).toBe("curl");
    });

    it("should normalize full-width unicode (NFKC) and ideographic spaces", () => {
      // Full-width latin ｃｕｒｌ and full-width ideographic space \u3000
      const fullWidth = "ｃｕｒｌ\u3000/etc/passwd";
      expect(normalizeUnicodeAndWhitespace(fullWidth)).toBe("curl /etc/passwd");
    });

    it("should collapse multiple consecutive spaces into a single space and trim edges", () => {
      const messySpaces = "   hello     world   ";
      expect(normalizeUnicodeAndWhitespace(messySpaces)).toBe("hello world");
    });
  });

  describe("Zero-width space & Unicode evasion injection detection", () => {
    it("should detect command injection even when obfuscated with zero-width spaces", () => {
      // attacker splits "curl" with zero-width spaces: c\u200Burl
      expect(() =>
        sanitizer.validate({ cmd: "echo safe; c\u200Bu\u200Crl http://malicious.site" }),
      ).toThrow(SanitizationViolationError);
    });

    it("should detect path traversal obfuscated with full-width dots/slashes or spaces", () => {
      // Obfuscated ../ with full-width characters or zero-width
      expect(() =>
        sanitizer.validate({ path: "..\u200B/..\u200B/etc/passwd" }),
      ).toThrow(SanitizationViolationError);
    });

    it("should detect shell injection using $IFS whitespace bypass", () => {
      expect(() =>
        sanitizer.validate({ query: "cat$IFS/etc/passwd" }),
      ).toThrow(SanitizationViolationError);

      expect(() =>
        sanitizer.validate({ query: "rm${IFS}-rf${IFS}/" }),
      ).toThrow(SanitizationViolationError);
    });
  });

  describe("High-entropy and PII detection in maskSensitiveArguments", () => {
    it("should mask high-entropy secret tokens embedded in non-sensitive keys", () => {
      const args = {
        query: "Find information with key sk-ant-api03-kJ8dK2jL91mN0pQ8rStUvWxYzAbCdEfGhIjKlMnOp for testing",
        description: "Standard natural language sentence that should stay clear",
      };

      const masked = maskSensitiveArguments(args);
      expect(masked.query).toContain("[HIGH_ENTROPY_REDACTED]");
      expect(masked.query).not.toContain("sk-ant-api03-kJ8dK2jL91mN0pQ8rStUvWxYzAbCdEfGhIjKlMnOp");
      expect(masked.description).toBe("Standard natural language sentence that should stay clear");
    });

    it("should mask Korean Resident Registration Number (RRN) in log payloads", () => {
      const args = {
        userNote: "Customer identification number is 950101-1234567 please verify",
      };

      const masked = maskSensitiveArguments(args);
      expect(masked.userNote).toContain("950101-*******");
      expect(masked.userNote).not.toContain("1234567");
    });
  });
});
