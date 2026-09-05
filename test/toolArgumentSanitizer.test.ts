import { describe, it, expect } from "vitest";
import {
  ToolArgumentSanitizer,
  SanitizationViolationError,
  maskSensitiveArguments,
} from "../src/policy/toolArgumentSanitizer.js";

describe("ToolArgumentSanitizer (Security Guardrails & Invariants)", () => {
  const sanitizer = new ToolArgumentSanitizer();

  describe("Path Traversal Detection", () => {
    it("should reject path traversal with relative parent segments (../)", () => {
      expect(() =>
        sanitizer.validate({ path: "../../../etc/passwd" }),
      ).toThrow(SanitizationViolationError);

      expect(() =>
        sanitizer.validate({ file: "src/../../secret.key" }),
      ).toThrow(SanitizationViolationError);
    });

    it("should reject windows-style path traversal (..\\)", () => {
      expect(() =>
        sanitizer.validate({ path: "..\\..\\windows\\win.ini" }),
      ).toThrow(SanitizationViolationError);
    });

    it("should reject direct access to critical Unix/Windows system paths", () => {
      expect(() =>
        sanitizer.validate({ file: "/etc/passwd" }),
      ).toThrow(SanitizationViolationError);

      expect(() =>
        sanitizer.validate({ file: "/etc/shadow" }),
      ).toThrow(SanitizationViolationError);

      expect(() =>
        sanitizer.validate({ file: "C:\\Windows\\System32\\cmd.exe" }),
      ).toThrow(SanitizationViolationError);
    });

    it("should reject null byte injection (%00, \\0)", () => {
      expect(() =>
        sanitizer.validate({ file: "image.png\0.php" }),
      ).toThrow(SanitizationViolationError);

      expect(() =>
        sanitizer.validate({ file: "test%00.txt" }),
      ).toThrow(SanitizationViolationError);
    });
  });

  describe("Command & Shell Injection Detection", () => {
    it("should reject shell chained command operators (; , &&, ||)", () => {
      expect(() =>
        sanitizer.validate({ query: "status; rm -rf /" }),
      ).toThrow(SanitizationViolationError);

      expect(() =>
        sanitizer.validate({ input: "npm run test && curl attacker.com" }),
      ).toThrow(SanitizationViolationError);

      expect(() =>
        sanitizer.validate({ cmd: "false || cat /etc/passwd" }),
      ).toThrow(SanitizationViolationError);
    });

    it("should reject pipe and subshell executions (|, ``, $())", () => {
      expect(() =>
        sanitizer.validate({ param: "cat file | grep secret" }),
      ).toThrow(SanitizationViolationError);

      expect(() =>
        sanitizer.validate({ expr: "echo `whoami`" }),
      ).toThrow(SanitizationViolationError);

      expect(() =>
        sanitizer.validate({ payload: "echo $(id)" }),
      ).toThrow(SanitizationViolationError);
    });

    it("should reject dangerous shell redirection operators (> / >> / <)", () => {
      expect(() =>
        sanitizer.validate({ output: "something > /tmp/evil" }),
      ).toThrow(SanitizationViolationError);
    });
  });

  describe("Nested and Complex Argument Traversals", () => {
    it("should recursively detect violations in nested objects and arrays", () => {
      expect(() =>
        sanitizer.validate({
          config: {
            deep: {
              target: "../../../etc/hosts",
            },
          },
        }),
      ).toThrow(SanitizationViolationError);

      expect(() =>
        sanitizer.validate({
          items: ["valid", "also_valid", { command: "test; cat /etc/passwd" }],
        }),
      ).toThrow(SanitizationViolationError);
    });

    it("should allow safe arguments without violations", () => {
      expect(() =>
        sanitizer.validate({
          query: "SELECT * FROM users WHERE id = 1",
          url: "https://api.example.com/v1/search?q=typescript",
          title: "Code Quality & Security Report",
          tags: ["security", "tdd", "ddd"],
          metadata: { author: "engineer", rating: 5 },
        }),
      ).not.toThrow();
    });
  });

  describe("Sensitive Argument Masking (Data Protection)", () => {
    it("should mask sensitive keys in audit logging payload", () => {
      const payload = {
        tool: "auth.login",
        apiKey: "sk-proj-1234567890abcdef",
        password: "super_secret_password",
        authToken: "Bearer eyJhbGciOi...",
        clientSecret: "sec_99999",
        normalParam: "public_value",
        nested: {
          privateKey: "-----BEGIN PRIVATE KEY-----",
          safeNote: "hello",
        },
      };

      const masked = maskSensitiveArguments(payload);

      expect(masked.apiKey).toBe("********");
      expect(masked.password).toBe("********");
      expect(masked.authToken).toBe("********");
      expect(masked.clientSecret).toBe("********");
      expect(masked.normalParam).toBe("public_value");
      expect((masked.nested as any).privateKey).toBe("********");
      expect((masked.nested as any).safeNote).toBe("hello");
    });
  });

  describe("ReDoS and Argument Size Quota Protection", () => {
    it("should reject excessively large argument strings exceeding MAX_ARGUMENT_STRING_LENGTH", () => {
      const hugeString = "A".repeat(65 * 1024); // 65KB
      expect(() =>
        sanitizer.validate({ content: hugeString }),
      ).toThrow(SanitizationViolationError);
    });
  });
});
