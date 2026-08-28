import { z } from "zod";

const schema = z.object({
  REDIS_HOST: z.string().trim().min(1).optional(),
  REDIS_PORT: z.coerce.number().int().min(1).max(65_535).default(6379),
  REDIS_PASSWORD: z.string().min(1).optional(),
});

export function loadRedisConfig(environment: NodeJS.ProcessEnv = process.env) {
  const parsed = schema.parse(environment);
  if (!parsed.REDIS_HOST || !parsed.REDIS_PASSWORD) {
    throw new Error("REDIS_HOST and REDIS_PASSWORD are required");
  }
  return {
    socket: { host: parsed.REDIS_HOST, port: parsed.REDIS_PORT },
    password: parsed.REDIS_PASSWORD,
  };
}
