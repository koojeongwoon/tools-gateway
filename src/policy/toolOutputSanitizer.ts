import { maskHighEntropyTokens } from "../crypto/entropy.js";

const KOREAN_RRN_PATTERN = /\b(\d{6})[- ]?([1-8]\d{6})\b/g;

/**
 * Sanitizes tool execution output before it is returned to LLMs or logged.
 * Protects against:
 * 1. Accidental high-entropy secret leaks in downstream tool outputs
 * 2. Multilingual PII leaks (Korean RRN, etc.)
 */
export function sanitizeToolResult<T>(result: T): T {
  if (result === null || result === undefined) return result;

  if (typeof result === "string") {
    let sanitized = result.replace(KOREAN_RRN_PATTERN, "$1-*******");
    sanitized = maskHighEntropyTokens(sanitized);
    return sanitized as unknown as T;
  }

  if (Array.isArray(result)) {
    return result.map((item) => sanitizeToolResult(item)) as unknown as T;
  }

  if (typeof result === "object") {
    const sanitizedObj: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(result)) {
      sanitizedObj[key] = sanitizeToolResult(value);
    }
    return sanitizedObj as T;
  }

  return result;
}
