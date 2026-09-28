import { z } from "zod";

const jevConfigSchema = z.object({
  JEV_API_KEY: z.string().trim().min(1).optional(),
  TYPESAFE_API_KEY: z.string().trim().min(1).optional(),
  JEV_ENDPOINT: z.string().url().default("https://api.typesafe.ai"),
  JEV_MODEL: z.string().min(1).default("jev-latest"),
  JEV_TIMEOUT_MS: z.coerce.number().int().positive().default(500),
  JEV_GUARDRAIL_ENABLED: z
    .string()
    .transform((val) => val.toLowerCase() === "true")
    .default(true),
  JEV_RISK_THRESHOLD: z.coerce.number().min(0).max(1).default(0.85),
  JEV_ROUTER_ENABLED: z
    .string()
    .transform((val) => val.toLowerCase() === "true")
    .default(true),
});

export type JevRawConfig = z.infer<typeof jevConfigSchema>;

export interface JevConfig {
  apiKey: string | undefined;
  endpoint: string;
  model: string;
  timeoutMs: number;
  guardrailEnabled: boolean;
  riskThreshold: number;
  routerEnabled: boolean;
}

export function loadJevConfig(environment: NodeJS.ProcessEnv = process.env): JevConfig {
  const parsed = jevConfigSchema.parse(environment);
  const apiKey = parsed.JEV_API_KEY || parsed.TYPESAFE_API_KEY;

  return {
    apiKey,
    endpoint: parsed.JEV_ENDPOINT.replace(/\/+$/, ""),
    model: parsed.JEV_MODEL,
    timeoutMs: parsed.JEV_TIMEOUT_MS,
    guardrailEnabled: parsed.JEV_GUARDRAIL_ENABLED && Boolean(apiKey),
    riskThreshold: parsed.JEV_RISK_THRESHOLD,
    routerEnabled: parsed.JEV_ROUTER_ENABLED && Boolean(apiKey),
  };
}
