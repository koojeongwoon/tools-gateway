import { z } from "zod";

/**
 * Domain DTO schemas & Transformers (Hexagonal Adapter pattern)
 */
export const CreateKeyRequestDto = z.object({
  name: z.string().trim().min(1).max(100),
  expiresAt: z.string().datetime({ offset: true }).optional(),
});
export type CreateKeyRequestDto = z.infer<typeof CreateKeyRequestDto>;

export const CreateUpstreamRequestDto = z.object({
  toolPrefix: z.string().trim().min(1).max(50).regex(/^[a-z][a-z0-9_]{0,49}$/),
  endpointUrl: z.string().trim().url(),
  transport: z.enum(["streamable-http", "sse"]).default("streamable-http"),
  authType: z.enum(["bearer", "api_key", "custom_header", "none"]).default("bearer"),
  authHeaderName: z.string().trim().min(1).max(100).default("Authorization"),
  authValue: z.string().trim().optional(),
  description: z.string().trim().max(255).optional(),
});
export type CreateUpstreamRequestDto = z.infer<typeof CreateUpstreamRequestDto>;

export const SaveAiKeyRequestDto = z.object({
  provider: z.enum(["OPENAI_API_KEY", "EMBEDDING_API_KEY"]),
  apiKey: z.string().trim().min(1),
  accountType: z.enum(["USER", "ORGANIZATION"]).default("USER"),
});
export type SaveAiKeyRequestDto = z.infer<typeof SaveAiKeyRequestDto>;

export const CheckDeviceRequestDto = z.object({
  deviceAuthId: z.string().trim().min(1),
  userCode: z.string().trim().min(1),
  accountType: z.enum(["USER", "ORGANIZATION"]).default("USER"),
});
export type CheckDeviceRequestDto = z.infer<typeof CheckDeviceRequestDto>;

export class ManagementDtoAdapter {
  static parseCreateKey(input: unknown): CreateKeyRequestDto {
    return CreateKeyRequestDto.parse(input);
  }

  static parseCreateUpstream(input: unknown): CreateUpstreamRequestDto {
    return CreateUpstreamRequestDto.parse(input);
  }

  static parseSaveAiKey(input: unknown): SaveAiKeyRequestDto {
    return SaveAiKeyRequestDto.parse(input);
  }

  static parseCheckDevice(input: unknown): CheckDeviceRequestDto {
    return CheckDeviceRequestDto.parse(input);
  }
}
