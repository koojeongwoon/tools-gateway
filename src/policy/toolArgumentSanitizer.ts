import { maskHighEntropyTokens } from "../crypto/entropy.js";

export class SanitizationViolationError extends Error {
  readonly statusCode = 400;
  readonly code = "SECURITY_VIOLATION";

  constructor(message: string, readonly field?: string, readonly pattern?: string) {
    super(`Tool argument security violation: ${message}`);
    this.name = "SanitizationViolationError";
  }
}

/**
 * Normalizes unicode, strips zero-width non-printing characters used for bypasses,
 * normalizes full-width characters (NFKC), and cleans excess whitespace.
 */
export function normalizeUnicodeAndWhitespace(text: string): string {
  if (!text || typeof text !== "string") return text;

  return text
    // 1. Unicode NFKC normalization (turns full-width characters into standard ASCII)
    .normalize("NFKC")
    // 2. Remove invisible zero-width characters and directional overrides
    // \u200B (ZWSP), \u200C (ZWNJ), \u200D (ZWJ), \uFEFF (BOM), \u200E/\u200F (LTR/RTL marks), \u2060 (word joiner)
    .replace(/[\u200B-\u200D\uFEFF\u200E\u200F\u2060]/g, "")
    // 3. Convert all non-standard spaces (\u00A0 NBSP, \u3000 ideographic space, \u2000-\u200A) to standard space
    .replace(/[\u00A0\u3000\u2000-\u200A]/g, " ")
    // 4. Collapse multiple spaces into single space and trim edges
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Patterns matching path traversal attempts
 */
const PATH_TRAVERSAL_PATTERNS = [
  /(?:^|[\\/])\.\.(?:[\\/]|$)/, // ../ or ..\
  /\0|%00/i, // null bytes
  /(?:^|[\\/])etc[\\/](?:passwd|shadow|hosts)/i, // sensitive unix files
  /(?:^|[\\/])windows[\\/]system32/i, // sensitive windows files
  /(?:^|[\\/])proc[\\/]self/i, // linux /proc/self
];

/**
 * Patterns matching dangerous shell operators & command injection, including $IFS tricks
 */
const COMMAND_INJECTION_PATTERNS = [
  /[;&|`$](?:\s+|\$\{?IFS\}?)*(?:rm|cat|ls|whoami|curl|wget|bash|sh|zsh|python|node|id|kill|pkill|grep|awk|sed)\b/i,
  /;\s*[^;]+/, // command chaining with semicolon
  /&&|\|\|/, // command chaining with and/or
  /\|(?!\s*\|)\s*[^|]+/, // pipe to another command
  /`[^`]+`/, // backtick command substitution
  /\$\([^)]+\)/, // $() subshell command substitution
  /\$\{?IFS\}?/, // Shell Internal Field Separator whitespace bypass
  /[<>]\s*\/[a-zA-Z0-9_.-]+/, // file redirection to root or path
];

const SENSITIVE_KEY_PATTERNS = [
  /password/i,
  /secret/i,
  /token/i,
  /apikey|api_key/i,
  /auth/i,
  /credential/i,
  /private_?key/i,
  /certificate/i,
];

// Multilingual PII Patterns (Korean RRN: 6 digits - 7 digits)
const KOREAN_RRN_PATTERN = /\b(\d{6})[- ]?([1-8]\d{6})\b/g;

export interface SanitizerOptions {
  /** If true, strictly check for command injection and path traversal */
  strict?: boolean;
}

export const MAX_ARGUMENT_STRING_LENGTH = 64 * 1024; // 64KB per string argument

export class ToolArgumentSanitizer {
  constructor(private readonly options: SanitizerOptions = { strict: true }) {}

  validate(arguments_: Record<string, unknown>): void {
    if (!this.options.strict) return;
    this.traverseAndValidate(arguments_, "");
  }

  private traverseAndValidate(value: unknown, path: string): void {
    if (value === null || value === undefined) return;

    if (typeof value === "string") {
      this.checkStringValue(value, path);
    } else if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        this.traverseAndValidate(value[i], `${path}[${i}]`);
      }
    } else if (typeof value === "object") {
      for (const [key, val] of Object.entries(value)) {
        this.traverseAndValidate(val, path ? `${path}.${key}` : key);
      }
    }
  }

  private checkStringValue(val: string, path: string): void {
    // 0. ReDoS and Memory Exhaustion Check
    if (val.length > MAX_ARGUMENT_STRING_LENGTH) {
      throw new SanitizationViolationError(
        `Argument string length (${val.length}) exceeds maximum limit (${MAX_ARGUMENT_STRING_LENGTH})`,
        path,
        "MAX_ARGUMENT_STRING_LENGTH",
      );
    }

    // Defense-in-depth: Normalize unicode and strip zero-width evasion characters before inspecting
    const normalized = normalizeUnicodeAndWhitespace(val);

    // 1. Path Traversal Check (check both raw and normalized)
    for (const pattern of PATH_TRAVERSAL_PATTERNS) {
      if (pattern.test(val) || pattern.test(normalized)) {
        throw new SanitizationViolationError(
          `Detected potential Path Traversal attack in parameter '${path}'`,
          path,
          pattern.source,
        );
      }
    }

    // 2. Command Injection Check (check both raw and normalized)
    for (const pattern of COMMAND_INJECTION_PATTERNS) {
      if (pattern.test(val) || pattern.test(normalized)) {
        throw new SanitizationViolationError(
          `Detected potential Command Injection in parameter '${path}'`,
          path,
          pattern.source,
        );
      }
    }
  }
}

/**
 * Masks sensitive arguments for audit logging and diagnostics (Data Protection P2)
 * Incorporates:
 * 1. Sensitive Key Name Matching
 * 2. High-Entropy Secret Detection (Shannon Entropy)
 * 3. Multilingual PII Masking (e.g., Korean RRN)
 */
export function maskSensitiveArguments<T extends Record<string, unknown>>(args: T): T {
  if (!args || typeof args !== "object") return args;
  return deepMask(args) as T;
}

function deepMask(val: unknown): unknown {
  if (val === null || val === undefined) return val;

  if (Array.isArray(val)) {
    return val.map((item) => deepMask(item));
  }

  if (typeof val === "object") {
    const maskedObj: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(val)) {
      const isSensitiveKey = SENSITIVE_KEY_PATTERNS.some((p) => p.test(key));
      if (isSensitiveKey && typeof value === "string") {
        maskedObj[key] = "********";
      } else if (typeof value === "object" && value !== null) {
        maskedObj[key] = deepMask(value);
      } else if (typeof value === "string") {
        // Apply Multilingual PII Masking and High-Entropy Token Redaction
        let processed = value.replace(KOREAN_RRN_PATTERN, "$1-*******");
        processed = maskHighEntropyTokens(processed);
        maskedObj[key] = isSensitiveKey ? "********" : processed;
      } else {
        maskedObj[key] = isSensitiveKey ? "********" : value;
      }
    }
    return maskedObj;
  }

  return val;
}
