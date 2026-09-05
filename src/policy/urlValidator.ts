import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

export class SsrFViolationError extends Error {
  readonly statusCode = 400;
  readonly code = "SSRF_VIOLATION";

  constructor(message: string) {
    super(`SSRF Protection Violation: ${message}`);
    this.name = "SsrFViolationError";
  }
}

/**
 * Checks if an IPv4 or IPv6 address belongs to private/internal/reserved ranges
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  // Normalize IPv6 mapped IPv4 (e.g. ::ffff:127.0.0.1)
  const normalized = ip.replace(/^::ffff:/i, "");

  // Localhost & Loopback
  if (normalized === "127.0.0.1" || normalized === "::1" || normalized === "0.0.0.0" || normalized === "::") {
    return true;
  }

  // IPv4 Private & Link-local ranges
  // 10.0.0.0/8
  if (normalized.startsWith("10.")) return true;

  // 192.168.0.0/16
  if (normalized.startsWith("192.168.")) return true;

  // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
  if (/^172\.(?:1[6-9]|2[0-9]|3[01])\./.test(normalized)) return true;

  // 169.254.0.0/16 (Link-local & AWS/GCP/Azure Instance Metadata 169.254.169.254)
  if (normalized.startsWith("169.254.")) return true;

  // 100.64.0.0/10 (Carrier Grade NAT)
  if (/^100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./.test(normalized)) return true;

  // IPv6 Private & Local (fc00::/7 unique local, fe80::/10 link-local)
  const lower = normalized.toLowerCase();
  if (lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("fe80")) {
    return true;
  }

  return false;
}

/**
 * Validates that an endpoint URL is safe from SSRF attacks before registration or invocation.
 */
export async function validateSafeEndpointUrl(rawUrl: string): Promise<void> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new SsrFViolationError(`Invalid URL format: '${rawUrl}'`);
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new SsrFViolationError(`Forbidden protocol '${parsed.protocol}'. Only http: and https: are allowed.`);
  }

  const hostname = parsed.hostname.toLowerCase();

  // Hostname string checks
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  ) {
    throw new SsrFViolationError(`Forbidden internal hostname: '${hostname}'`);
  }

  // If host is a direct IP address literal
  const cleanHost = hostname.replace(/^\[|\]$/g, ""); // strip IPv6 brackets
  if (isIP(cleanHost)) {
    if (isPrivateOrReservedIp(cleanHost)) {
      throw new SsrFViolationError(`Access to private or local IP address '${cleanHost}' is forbidden`);
    }
    return;
  }

  // Otherwise resolve domain via DNS
  try {
    const { address } = await lookup(hostname);
    if (isPrivateOrReservedIp(address)) {
      throw new SsrFViolationError(
        `Hostname '${hostname}' resolves to private or internal IP '${address}'`,
      );
    }
  } catch (error) {
    if (error instanceof SsrFViolationError) throw error;
    // DNS resolution failure
    throw new SsrFViolationError(`Failed to resolve hostname '${hostname}': ${(error as Error).message}`);
  }
}
