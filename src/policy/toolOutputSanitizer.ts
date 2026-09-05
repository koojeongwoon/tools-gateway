import { maskHighEntropyTokens } from "../crypto/entropy.js";

const KOREAN_RRN_PATTERN = /\b(\d{6})[- ]?([1-8]\d{6})\b/g;

/**
 * Maximum allowed single text output length from a tool (2MB = ~2,000,000 chars).
 * Prevents Denial-of-Service / Memory exhaustion attacks on the gateway and LLM.
 */
export const MAX_TOOL_OUTPUT_TEXT_LENGTH = 2 * 1024 * 1024;

/**
 * Encapsulates untrusted tool output in standardized boundary tags.
 * Neutralizes any attempts by the content to break out of the tag.
 */
export function encapsulateUntrustedToolOutput(content: string): string {
  // Strip any internal attempts to close or spoof boundary tags
  const neutralized = content.replace(/<\/?untrusted_tool_output>/gi, "");
  return `<untrusted_tool_output>\n${neutralized}\n</untrusted_tool_output>`;
}

/**
 * Sanitizes tool execution output before it is returned to LLMs or logged.
 * Protects against:
 * 1. Accidental high-entropy secret leaks in downstream tool outputs
 * 2. Multilingual PII leaks (Korean RRN, etc.)
 * 3. Oversized payload DoS / memory bloat
 */
export function sanitizeToolResult(result: unknown): any {
  if (result === null || result === undefined) return result;

  if (typeof result === "string") {
    let text: string = result;

    // 1. Guard against payload DoS / Memory exhaustion
    if (text.length > MAX_TOOL_OUTPUT_TEXT_LENGTH) {
      text =
        text.slice(0, MAX_TOOL_OUTPUT_TEXT_LENGTH) +
        "\n... [TRUNCATED: Tool output exceeded maximum length]";
    }

    // 2. Multilingual PII Masking
    text = text.replace(KOREAN_RRN_PATTERN, "$1-*******");

    // 3. High-entropy Secret Redaction
    text = maskHighEntropyTokens(text);

    return text;
  }

  if (Array.isArray(result)) {
    return result.map((item) => sanitizeToolResult(item));
  }

  if (typeof result === "object") {
    const sanitizedObj: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(result)) {
      sanitizedObj[key] = sanitizeToolResult(value);
    }
    return sanitizedObj;
  }

  return result;
}
