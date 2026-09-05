/**
 * Shannon Entropy calculation and Secret Leak Detection for AI Gateway & MCP Tools.
 * High entropy strings (Base64, Hex, Cryptographic API tokens, private keys)
 * exhibit high information density compared to natural language or source code.
 */

export interface EntropyOptions {
  /** Minimum length of a token to evaluate entropy for (default: 16) */
  minLength?: number;
  /** Shannon entropy threshold in bits/character (default: 4.2) */
  threshold?: number;
}

/**
 * Calculates the Shannon Entropy (in bits per character) for a given string:
 * H(X) = - \sum_{i=1}^{n} P(x_i) * log2(P(x_i))
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const frequencies = new Map<string, number>();
  for (let i = 0; i < str.length; i++) {
    const char = str.charAt(i);
    frequencies.set(char, (frequencies.get(char) ?? 0) + 1);
  }

  const len = str.length;
  let entropy = 0;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

const DEFAULT_MIN_LENGTH = 16;
const DEFAULT_ENTROPY_THRESHOLD = 4.2;

/**
 * Checks if a candidate string is likely a high-entropy secret token.
 */
export function isHighEntropyString(
  token: string,
  options: EntropyOptions = {},
): boolean {
  const minLength = options.minLength ?? DEFAULT_MIN_LENGTH;
  const threshold = options.threshold ?? DEFAULT_ENTROPY_THRESHOLD;

  if (token.length < minLength) return false;

  // Well-known false positive exclusions: UUIDs with hyphens, pure numbers, repetitive patterns
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)) {
    return false; // Standard UUIDs have predictable structure
  }

  const entropy = calculateShannonEntropy(token);
  return entropy >= threshold;
}

/**
 * Regular expression matching potential alphanumeric/base64/hex tokens
 */
const POTENTIAL_SECRET_TOKEN_REGEX = /(?:[A-Za-z0-9+/=_-]{16,})/g;

/**
 * Extracts candidate high-entropy tokens from a text string.
 */
export function findHighEntropyTokens(
  text: string,
  options: EntropyOptions = {},
): string[] {
  if (!text || typeof text !== "string") return [];

  const matches = text.match(POTENTIAL_SECRET_TOKEN_REGEX);
  if (!matches) return [];

  const highEntropyTokens: string[] = [];
  for (const candidate of matches) {
    if (isHighEntropyString(candidate, options)) {
      highEntropyTokens.push(candidate);
    }
  }

  return highEntropyTokens;
}

/**
 * Redacts high entropy tokens from a text string, preventing sensitive secret leaks in logs.
 */
export function maskHighEntropyTokens(
  text: string,
  options: EntropyOptions = {},
): string {
  if (!text || typeof text !== "string") return text;

  return text.replace(POTENTIAL_SECRET_TOKEN_REGEX, (token) => {
    if (isHighEntropyString(token, options)) {
      return "[HIGH_ENTROPY_REDACTED]";
    }
    return token;
  });
}
