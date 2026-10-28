import { describe, expect, it } from "vitest";
import { resolveMcpNamingDelimiter } from "../src/api/mcpRoutes.js";

describe("resolveMcpNamingDelimiter", () => {
  it("defaults to dot (.) for standard clients like Cursor", () => {
    const req: any = {
      query: {},
      headers: {
        "user-agent": "Cursor/0.42.0",
      },
    };
    expect(resolveMcpNamingDelimiter(req)).toBe(".");
  });

  it("selects underscore (_) when query delimiter=_ is present", () => {
    const req: any = {
      query: { delimiter: "_" },
      headers: {},
    };
    expect(resolveMcpNamingDelimiter(req)).toBe("_");
  });

  it("selects underscore (_) when query naming=underscore is present", () => {
    const req: any = {
      query: { naming: "underscore" },
      headers: {},
    };
    expect(resolveMcpNamingDelimiter(req)).toBe("_");
  });

  it("selects underscore (_) when query naming=flat is present", () => {
    const req: any = {
      query: { naming: "flat" },
      headers: {},
    };
    expect(resolveMcpNamingDelimiter(req)).toBe("_");
  });

  it("selects underscore (_) when x-mcp-delimiter header is _", () => {
    const req: any = {
      query: {},
      headers: {
        "x-mcp-delimiter": "_",
      },
    };
    expect(resolveMcpNamingDelimiter(req)).toBe("_");
  });

  it("selects underscore (_) automatically for Antigravity User-Agent", () => {
    const req1: any = {
      query: {},
      headers: {
        "user-agent": "Antigravity/1.0",
      },
    };
    expect(resolveMcpNamingDelimiter(req1)).toBe("_");

    const req2: any = {
      query: {},
      headers: {
        "user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) antigravity/2.27.0",
      },
    };
    expect(resolveMcpNamingDelimiter(req2)).toBe("_");
  });
});
