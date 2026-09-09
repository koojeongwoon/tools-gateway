import { findHighEntropyTokens } from "../crypto/entropy.js";
import { normalizeUnicodeAndWhitespace } from "./toolArgumentSanitizer.js";

const SENSITIVE_ARGUMENT_KEY_PATTERNS = [
  /password/i,
  /secret/i,
  /token/i,
  /apikey|api_key/i,
  /auth/i,
  /credential/i,
  /private_?key/i,
  /certificate/i,
];

/** Prevents a caller from exfiltrating secrets through an upstream tool argument. */
export class SecretEgressBlockedError extends Error {
  readonly statusCode = 400;
  readonly code = "SECRET_EGRESS_BLOCKED";

  constructor(readonly field: string) {
    super(`SECRET_EGRESS_BLOCKED: outbound tool call blocked for argument '${field}'`);
    this.name = "SecretEgressBlockedError";
  }
}

/**
 * Gateway credentials are injected into configured upstream headers, never
 * accepted as MCP tool arguments. This guard enforces that boundary before an
 * upstream connection receives the request.
 */
export class OutboundSecretLeakGuard {
  validate(arguments_: Record<string, unknown>): void {
    this.traverse(arguments_, "");
  }

  private traverse(value: unknown, path: string): void {
    if (value === null || value === undefined) return;

    if (typeof value === "string") {
      if (findHighEntropyTokens(normalizeUnicodeAndWhitespace(value)).length > 0) {
        throw new SecretEgressBlockedError(path || "<root>");
      }
      return;
    }

    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index++) {
        this.traverse(value[index], `${path}[${index}]`);
      }
      return;
    }

    if (typeof value === "object") {
      for (const [key, nestedValue] of Object.entries(value)) {
        const nestedPath = path ? `${path}.${key}` : key;
        if (
          nestedValue !== null
          && nestedValue !== undefined
          && SENSITIVE_ARGUMENT_KEY_PATTERNS.some((pattern) => pattern.test(key))
        ) {
          throw new SecretEgressBlockedError(nestedPath);
        }
        this.traverse(nestedValue, nestedPath);
      }
    }
  }
}
