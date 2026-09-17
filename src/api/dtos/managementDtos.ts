import { z } from "zod";

/**
 * Domain DTO schemas & Transformers (Hexagonal Adapter pattern)
 */
export const CreateKeyRequestDto = z.object({
  name: z.string().trim().min(1).max(100),
  expiresAt: z.string().datetime({ offset: true }).optional(),
  toolPatterns: z.array(
    z.string().regex(/^[A-Za-z0-9_-]+\.(\*|[A-Za-z0-9_.-]+\*?)$/),
  ).min(1).max(100).optional(),
});
export type CreateKeyRequestDto = z.infer<typeof CreateKeyRequestDto>;

export const CreateUpstreamRequestDto = z.object({
  toolPrefix: z.string().trim().min(1).max(50).regex(/^[a-z][a-z0-9_]{0,49}$/),
  endpointUrl: z.string().trim().url(),
  // Self-service URLs never receive an IAM-delegated user identity.
  authMode: z.literal("provider-credential"),
  // Custom upstreams support Streamable HTTP only.
  transport: z.literal("streamable-http").default("streamable-http"),
  authType: z.enum(["bearer", "api_key", "custom_header", "none"]).default("bearer"),
  authHeaderName: z.string().trim().min(1).max(100).default("Authorization"),
  authValue: z.string().trim().optional(),
  description: z.string().trim().max(255).optional(),
}).strict();
export type CreateUpstreamRequestDto = z.infer<typeof CreateUpstreamRequestDto>;

export class ManagementDtoAdapter {
  static parseCreateKey(input: unknown): CreateKeyRequestDto {
    return CreateKeyRequestDto.parse(input);
  }

  static parseCreateUpstream(input: unknown): CreateUpstreamRequestDto {
    return CreateUpstreamRequestDto.parse(input);
  }

}
