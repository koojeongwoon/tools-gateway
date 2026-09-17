import { describe, expect, it } from "vitest";
import { CreateUpstreamRequestDto } from "../src/api/dtos/managementDtos.js";

describe("custom upstream request DTO", () => {
  it("accepts only the implemented Streamable HTTP transport", () => {
    expect(CreateUpstreamRequestDto.safeParse({
      toolPrefix: "mygithub",
      endpointUrl: "https://mcp.example.com/mcp",
      authMode: "provider-credential",
      transport: "streamable-http",
    }).success).toBe(true);

    expect(CreateUpstreamRequestDto.safeParse({
      toolPrefix: "mygithub",
      endpointUrl: "https://mcp.example.com/sse",
      authMode: "provider-credential",
      transport: "sse",
    }).success).toBe(false);
  });

  it("requires provider credential mode for self-service URLs", () => {
    expect(CreateUpstreamRequestDto.safeParse({
      toolPrefix: "mygithub",
      endpointUrl: "https://mcp.example.com/mcp",
    }).success).toBe(false);

    expect(CreateUpstreamRequestDto.safeParse({
      toolPrefix: "mygithub",
      endpointUrl: "https://mcp.example.com/mcp",
      authMode: "gateway-delegation",
    }).success).toBe(false);
  });
});
