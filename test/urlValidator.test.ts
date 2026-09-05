import { describe, it, expect } from "vitest";
import { validateSafeEndpointUrl, SsrFViolationError } from "../src/policy/urlValidator.js";

describe("SSRF URL Validator (Zero-cost Network Guardrail)", () => {
  it("should allow valid public HTTPS and HTTP URLs", async () => {
    await expect(validateSafeEndpointUrl("https://api.github.com/mcp")).resolves.not.toThrow();
    await expect(validateSafeEndpointUrl("https://raw.githubusercontent.com/repo/spec.json")).resolves.not.toThrow();
  });

  it("should reject non-HTTP protocols (e.g. file:, ftp:, gopher:)", async () => {
    await expect(validateSafeEndpointUrl("file:///etc/passwd")).rejects.toThrow(SsrFViolationError);
    await expect(validateSafeEndpointUrl("ftp://ftp.example.com/file")).rejects.toThrow(SsrFViolationError);
    await expect(validateSafeEndpointUrl("gopher://127.0.0.1:70/")).rejects.toThrow(SsrFViolationError);
  });

  it("should reject localhost, loopback, and zero-addresses", async () => {
    await expect(validateSafeEndpointUrl("http://localhost:8080/mcp")).rejects.toThrow(SsrFViolationError);
    await expect(validateSafeEndpointUrl("http://127.0.0.1:3000/mcp")).rejects.toThrow(SsrFViolationError);
    await expect(validateSafeEndpointUrl("http://0.0.0.0:3000/mcp")).rejects.toThrow(SsrFViolationError);
    await expect(validateSafeEndpointUrl("http://[::1]:3000/mcp")).rejects.toThrow(SsrFViolationError);
  });

  it("should reject cloud instance metadata endpoints (169.254.169.254 / link-local)", async () => {
    await expect(validateSafeEndpointUrl("http://169.254.169.254/latest/meta-data/")).rejects.toThrow(SsrFViolationError);
    await expect(validateSafeEndpointUrl("http://169.254.1.1:8080/")).rejects.toThrow(SsrFViolationError);
  });

  it("should reject RFC 1918 private IPv4 subnets (10.x, 192.168.x, 172.16-31.x)", async () => {
    await expect(validateSafeEndpointUrl("http://10.0.0.5:8000/mcp")).rejects.toThrow(SsrFViolationError);
    await expect(validateSafeEndpointUrl("http://192.168.1.100:8000/mcp")).rejects.toThrow(SsrFViolationError);
    await expect(validateSafeEndpointUrl("http://172.20.0.2:8000/mcp")).rejects.toThrow(SsrFViolationError);
    await expect(validateSafeEndpointUrl("http://172.31.255.255:8000/mcp")).rejects.toThrow(SsrFViolationError);
  });

  it("should allow safe public class B 172.x subnets outside 172.16-31", async () => {
    // 172.32.0.1 is a public IP
    await expect(validateSafeEndpointUrl("http://172.32.0.1:8000/mcp")).resolves.not.toThrow();
  });
});
