import { describe, expect, it } from "vitest";
import { bearerToken } from "../src/auth/keyVerifier.js";

describe("API key authentication", () => {
  it("accepts exactly one Bearer token", () => {
    expect(bearerToken("Bearer tg_live_secret")).toBe("tg_live_secret");
    expect(bearerToken("bearer tg_live_secret")).toBeUndefined();
    expect(bearerToken("Bearer one two")).toBeUndefined();
    expect(bearerToken(undefined)).toBeUndefined();
  });
});
