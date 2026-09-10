import { describe, expect, it } from "vitest";
import { CreateUpstreamRequestDto, SaveAiKeyRequestDto } from "../src/api/dtos/managementDtos.js";

describe("custom upstream request DTO", () => {
  it("accepts only the implemented Streamable HTTP transport", () => {
    expect(CreateUpstreamRequestDto.safeParse({
      toolPrefix: "mygithub",
      endpointUrl: "https://mcp.example.com/mcp",
      transport: "streamable-http",
    }).success).toBe(true);

    expect(CreateUpstreamRequestDto.safeParse({
      toolPrefix: "mygithub",
      endpointUrl: "https://mcp.example.com/sse",
      transport: "sse",
    }).success).toBe(false);
  });

  it("does not include caller-selected AI credential ownership", () => {
    const parsed = SaveAiKeyRequestDto.parse({
      provider: "OPENAI_API_KEY",
      apiKey: "sk-test",
      accountType: "USER",
    });

    expect(parsed).toEqual({ provider: "OPENAI_API_KEY", apiKey: "sk-test" });
  });
});
