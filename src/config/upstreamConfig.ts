import { readFile } from "node:fs/promises";
import { parse } from "yaml";
import { z } from "zod";

const upstreamSchema = z
  .object({
    id: z.string().regex(/^[a-zA-Z0-9_-]+$/),
    toolPrefix: z.string().regex(/^[a-zA-Z0-9_-]+$/),
    networkScope: z.enum(["cluster", "external"]),
    endpoint: z.string().url(),
    transport: z.literal("streamable-http"),
    enabled: z.boolean().default(true),
    timeoutMs: z.number().int().positive().default(30_000),
    headers: z
      .record(
        z.string().regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/),
        z.object({ env: z.string().regex(/^[A-Z_][A-Z0-9_]*$/) }),
      )
      .default({}),
  })
  .superRefine(({ endpoint, networkScope }, ctx) => {
    const url = new URL(endpoint);

    if (networkScope === "cluster") {
      if (!isClusterServiceHostname(url.hostname)) {
        ctx.addIssue({
          code: "custom",
          path: ["endpoint"],
          message:
            "cluster upstream endpoint must use a Kubernetes Service hostname ending in .svc or .svc.cluster.local",
        });
      }
      return;
    }

    if (url.protocol !== "https:") {
      ctx.addIssue({
        code: "custom",
        path: ["endpoint"],
        message: "external upstream endpoint must use https",
      });
    }
    if (isForbiddenExternalHostname(url.hostname)) {
      ctx.addIssue({
        code: "custom",
        path: ["endpoint"],
        message:
          "external upstream endpoint must not target localhost, link-local, private, or Kubernetes Service addresses",
      });
    }
  });

const toolPolicySchema = z.object({
  default: z.literal("deny"),
  allow: z.array(z.string().min(1)),
  deny: z.array(z.string().min(1)).default([]),
});

const gatewayConfigSchema = z
  .object({
    upstreams: z.array(upstreamSchema),
    toolPolicy: toolPolicySchema,
  })
  .superRefine(({ upstreams }, ctx) => {
    for (const field of ["id", "toolPrefix"] as const) {
      const seen = new Set<string>();
      for (const upstream of upstreams) {
        if (seen.has(upstream[field])) {
          ctx.addIssue({
            code: "custom",
            message: `duplicate upstream ${field}: ${upstream[field]}`,
          });
        }
        seen.add(upstream[field]);
      }
    }
  });

export type UpstreamConfig = z.infer<typeof upstreamSchema>;
export type GatewayConfig = z.infer<typeof gatewayConfigSchema>;

export async function loadGatewayConfig(path: string): Promise<GatewayConfig> {
  const source = await readFile(path, "utf8");
  return gatewayConfigSchema.parse(parse(source));
}

export function parseGatewayConfig(value: unknown): GatewayConfig {
  return gatewayConfigSchema.parse(value);
}

export function resolveUpstreamHeaders(
  upstream: UpstreamConfig,
  environment: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const resolved: Record<string, string> = {};

  for (const [headerName, source] of Object.entries(upstream.headers)) {
    const value = environment[source.env];
    if (!value?.trim()) {
      throw new Error(
        `upstream '${upstream.id}' requires non-empty environment variable '${source.env}' for header '${headerName}'`,
      );
    }
    resolved[headerName] = value;
  }

  return resolved;
}

function isClusterServiceHostname(hostname: string): boolean {
  const normalized = hostname.toLowerCase().replace(/\.$/, "");
  return normalized.endsWith(".svc") || normalized.endsWith(".svc.cluster.local");
}

function isForbiddenExternalHostname(hostname: string): boolean {
  const normalized = hostname
    .toLowerCase()
    .replace(/\.$/, "")
    .replace(/^\[|\]$/g, "");
  if (
    normalized === "localhost" ||
    normalized.endsWith(".localhost") ||
    isClusterServiceHostname(normalized)
  ) {
    return true;
  }

  const octets = normalized.split(".").map(Number);
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet))) {
    return normalized === "::1" || normalized.startsWith("fe80:") || normalized.startsWith("fc") || normalized.startsWith("fd");
  }

  const [first, second] = octets as [number, number, number, number];
  return (
    first === 10 ||
    first === 127 ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  );
}
