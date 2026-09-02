import type { FastifyInstance } from "fastify";
import helmet from "@fastify/helmet";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";

export interface SecurityPluginOptions {
  corsOrigins?: string[] | string | boolean;
  rateLimitMax?: number;
  rateLimitTimeWindow?: string | number;
}

/**
 * Registers production-grade AppSec plugins:
 * 1. @fastify/helmet: Secures HTTP headers (CSP, HSTS, X-Content-Type-Options, etc.)
 * 2. @fastify/cors: Strict origin controls and allowed methods
 * 3. @fastify/rate-limit: Brute-force & DoS mitigation
 */
export async function registerSecurityPlugins(
  app: FastifyInstance,
  options?: SecurityPluginOptions,
): Promise<void> {
  // 1. Helmet for secure HTTP headers
  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'", // needed for dashboard scripts
          "https://static.cloudflareinsights.com",
        ],
        scriptSrcAttr: ["'unsafe-inline'"], // needed for inline event handlers (e.g. onclick)
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: [
          "'self'",
          "https://cloudflareinsights.com",
          "https://static.cloudflareinsights.com",
          "https://auth.snappytory.com",
        ],
        formAction: ["'self'", "https://auth.snappytory.com"],
        frameAncestors: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: false,
  });

  // 2. CORS configuration
  const allowOrigin = options?.corsOrigins ?? true;
  await app.register(cors, {
    origin: allowOrigin,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Session-ID", "Mcp-Session-Id"],
    credentials: true,
  });

  // 3. Global Rate Limiter
  await app.register(rateLimit, {
    max: options?.rateLimitMax ?? 1000,
    timeWindow: options?.rateLimitTimeWindow ?? "1 minute",
    errorResponseBuilder: (_req, context) => ({
      statusCode: 429,
      error: "Too Many Requests",
      message: `Rate limit exceeded. Try again in ${context.after}`,
    }),
  });
}
