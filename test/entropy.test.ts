import { describe, it, expect } from "vitest";
import {
  calculateShannonEntropy,
  isHighEntropyString,
  maskHighEntropyTokens,
  findHighEntropyTokens,
} from "../src/crypto/entropy.js";

describe("Shannon Entropy & Secret Leak Detection (Security & Data Protection)", () => {
  describe("calculateShannonEntropy", () => {
    it("should return 0 for empty string or single repeating character", () => {
      expect(calculateShannonEntropy("")).toBe(0);
      expect(calculateShannonEntropy("aaaaaaa")).toBe(0);
    });

    it("should return low entropy (< 3.8) for natural english or repetitive words", () => {
      const naturalText = "hello world this is a normal sentence";
      const entropy = calculateShannonEntropy(naturalText);
      expect(entropy).toBeLessThan(3.8);
    });

    it("should return high entropy (> 4.0) for random base64 / hex cryptographic keys", () => {
      // 32-byte / 256-bit high-entropy keys
      const secretKeyBase64 = "k9Xy+R2qW1zVbLm0Op3N8vC4x7AeG1uI6tFsY5hJ0kL=";
      const entropy = calculateShannonEntropy(secretKeyBase64);
      expect(entropy).toBeGreaterThan(4.5);

      const apiKey = "sk-ant-api03-kJ8dK2jL91mN0pQ8rStUvWxYzAbCdEfGhIjKlMnOp";
      expect(calculateShannonEntropy(apiKey)).toBeGreaterThan(4.3);
    });
  });

  describe("isHighEntropyString", () => {
    it("should identify high entropy cryptographic tokens", () => {
      const rawToken = "dGhpc19pc19hX3JhbmRvbV9zZWNyZXRfdG9rZW5fMTIzNDU2";
      expect(isHighEntropyString(rawToken, { minLength: 16, threshold: 4.0 })).toBe(true);
    });

    it("should not flag normal short words or standard text", () => {
      expect(isHighEntropyString("short", { minLength: 16 })).toBe(false);
      expect(isHighEntropyString("SELECT id, name, created_at FROM users WHERE status = 'active';", { minLength: 16, threshold: 4.5 })).toBe(false);
    });
  });

  describe("maskHighEntropyTokens", () => {
    it("should redact high entropy tokens embedded within text or arguments", () => {
      const textWithSecret = "Authorization failed for key sk-ant-api03-kJ8dK2jL91mN0pQ8rStUvWxYzAbCdEfGhIjKlMnOp please verify";
      const masked = maskHighEntropyTokens(textWithSecret);

      expect(masked).not.toContain("sk-ant-api03-kJ8dK2jL91mN0pQ8rStUvWxYzAbCdEfGhIjKlMnOp");
      expect(masked).toContain("[HIGH_ENTROPY_REDACTED]");
    });

    it("should keep normal natural language intact without false positive redacting", () => {
      const normalLog = "User requested tool execution with valid query and standard parameters.";
      expect(maskHighEntropyTokens(normalLog)).toBe(normalLog);
    });
  });

  describe("findHighEntropyTokens", () => {
    it("should extract list of suspect leaked secret tokens", () => {
      const payload = "Connecting with AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY and region us-east-1";
      const tokens = findHighEntropyTokens(payload);
      expect(tokens.length).toBeGreaterThanOrEqual(1);
      expect(tokens[0]).toContain("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    });
  });
});
