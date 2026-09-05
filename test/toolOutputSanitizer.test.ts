import { describe, it, expect } from "vitest";
import { sanitizeToolResult } from "../src/policy/toolOutputSanitizer.js";

describe("Tool Output Sanitization (AI Security & Leak Prevention)", () => {
  it("should redact high-entropy keys leaked in tool response text content", () => {
    const rawResult = {
      content: [
        {
          type: "text",
          text: "Database connected with credentials sk-ant-api03-kJ8dK2jL91mN0pQ8rStUvWxYzAbCdEfGhIjKlMnOp successfully",
        },
      ],
    };

    const sanitized = sanitizeToolResult(rawResult);
    const text = (sanitized.content as any)[0].text;
    expect(text).not.toContain("sk-ant-api03-kJ8dK2jL91mN0pQ8rStUvWxYzAbCdEfGhIjKlMnOp");
    expect(text).toContain("[HIGH_ENTROPY_REDACTED]");
  });

  it("should redact Korean Resident Registration Numbers leaked in tool response", () => {
    const rawResult = {
      content: [
        {
          type: "text",
          text: "User profile found: Name: Hong Gil Dong, RRN: 880101-1234567",
        },
      ],
    };

    const sanitized = sanitizeToolResult(rawResult);
    const text = (sanitized.content as any)[0].text;
    expect(text).toContain("880101-*******");
    expect(text).not.toContain("1234567");
  });

  it("should preserve normal text and structured tool output", () => {
    const rawResult = {
      content: [
        {
          type: "text",
          text: "Found 3 results matching 'typescript testing'.",
        },
      ],
      isError: false,
    };

    const sanitized = sanitizeToolResult(rawResult);
    expect(sanitized).toEqual(rawResult);
  });
});
