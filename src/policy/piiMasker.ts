/**
 * Comprehensive PII (Personally Identifiable Information) masking utilities for Tools Gateway.
 * Supports:
 * 1. Korean Resident Registration Number (RRN) / Alien Registration Number (ARC)
 * 2. Mobile and landline phone numbers (KR / Global format)
 * 3. Email addresses
 * 4. Credit card numbers (15-16 digits)
 */

// 1. Korean RRN / Alien Registration Number (6 digits - 7 digits)
const KOREAN_RRN_REGEX = /\b(\d{6})[- ]?([1-8]\d{6})\b/g;

// 2. Phone Numbers: captures 010-1234-5678, 010 1234 5678, 02-123-4567, etc.
const KR_PHONE_REGEX = /(?:\+?82[- ]?|0)(1[0-9]|2|[3-6][1-5]|70)[- ]?(\d{3,4})[- ]?(\d{4})\b/g;

// 3. Email Address
// e.g. hong.gildong@example.com -> h***g@example.com, a@test.com -> a***@test.com
const EMAIL_REGEX = /\b([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b/g;

// 4. Credit Card (16 digits: 4-4-4-4 or with hyphens/spaces)
const CREDIT_CARD_REGEX = /\b(\d{4})[- ]?(\d{4})[- ]?(\d{4})[- ]?(\d{4})\b/g;

/**
 * Masks all recognized PII patterns from text.
 */
export function maskPii(text: string): string {
  if (!text || typeof text !== "string") return text;

  let masked = text;

  // 1. Credit Cards: 1234-5678-9012-3456 -> 1234-****-****-3456
  masked = masked.replace(CREDIT_CARD_REGEX, "$1-****-****-$4");

  // 2. Korean RRN: 880101-1234567 -> 880101-*******
  masked = masked.replace(KOREAN_RRN_REGEX, "$1-*******");

  // 3. Korean Phone Numbers: 010-1234-5678 -> 010-****-5678, 010 1234 5678 -> 010-****-5678, 02-123-4567 -> 02-***-4567
  masked = masked.replace(KR_PHONE_REGEX, (_match, prefix: string, mid: string, last: string) => {
    const maskedMid = "*".repeat(mid.length);
    const normalizedPrefix = prefix.startsWith("0") ? prefix : `0${prefix}`;
    return `${normalizedPrefix}-${maskedMid}-${last}`;
  });

  // 4. Email addresses:
  masked = masked.replace(EMAIL_REGEX, (_match, user: string, domain: string) => {
    if (user.length <= 1) {
      return `${user}***@${domain}`;
    }
    const firstChar = user.charAt(0);
    const lastChar = user.charAt(user.length - 1);
    return `${firstChar}***${lastChar}@${domain}`;
  });

  return masked;
}

/**
 * Recursively scans and masks PII in an object, array, or primitive.
 */
export function deepMaskPii<T>(val: T): T {
  if (val === null || val === undefined) return val;

  if (typeof val === "string") {
    return maskPii(val) as unknown as T;
  }

  if (Array.isArray(val)) {
    return val.map((item) => deepMaskPii(item)) as unknown as T;
  }

  if (typeof val === "object") {
    const maskedObj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      maskedObj[k] = deepMaskPii(v);
    }
    return maskedObj as unknown as T;
  }

  return val;
}
