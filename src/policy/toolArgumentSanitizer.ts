export class SanitizationViolationError extends Error {
  readonly statusCode = 400;
  readonly code = "SECURITY_VIOLATION";

  constructor(message: string, readonly field?: string, readonly pattern?: string) {
    super(`Tool argument security violation: ${message}`);
    this.name = "SanitizationViolationError";
  }
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
 * Patterns matching dangerous shell operators & command injection
 */
const COMMAND_INJECTION_PATTERNS = [
  /[;&|`$]\s*(?:rm|cat|ls|whoami|curl|wget|bash|sh|zsh|python|node|id|kill|pkill|grep|awk|sed)\b/i,
  /;\s*[^;]+/, // command chaining with semicolon
  /&&|\|\|/, // command chaining with and/or
  /\|(?!\s*\|)\s*[^|]+/, // pipe to another command
  /`[^`]+`/, // backtick command substitution
  /\$\([^)]+\)/, // $() subshell command substitution
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

export interface SanitizerOptions {
  /** If true, strictly check for command injection and path traversal */
  strict?: boolean;
}

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
    // 1. Path Traversal Check
    for (const pattern of PATH_TRAVERSAL_PATTERNS) {
      if (pattern.test(val)) {
        throw new SanitizationViolationError(
          `Detected potential Path Traversal attack in parameter '${path}'`,
          path,
          pattern.source,
        );
      }
    }

    // 2. Command Injection Check
    for (const pattern of COMMAND_INJECTION_PATTERNS) {
      if (pattern.test(val)) {
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
      const isSensitive = SENSITIVE_KEY_PATTERNS.some((p) => p.test(key));
      if (isSensitive && typeof value === "string") {
        maskedObj[key] = "********";
      } else if (typeof value === "object" && value !== null) {
        maskedObj[key] = deepMask(value);
      } else {
        maskedObj[key] = isSensitive ? "********" : value;
      }
    }
    return maskedObj;
  }

  return val;
}
