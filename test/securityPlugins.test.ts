import { describe, it, expect } from "vitest";
import Fastify from "fastify";
import { registerSecurityPlugins } from "../src/server/registerSecurityPlugins.js";

describe("registerSecurityPlugins (AppSec - Helmet, CORS, Rate Limit)", () => {
  it("should attach security headers via helmet", async () => {
    const app = Fastify();
    await registerSecurityPlugins(app);
    app.get("/test", async () => ({ status: "ok" }));

    const res = await app.inject({
      method: "GET",
      url: "/test",
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers["x-dns-prefetch-control"]).toBe("off");
    expect(res.headers["x-frame-options"]).toBe("SAMEORIGIN");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["content-security-policy"]).toBeDefined();
    await app.close();
  });

  it("should handle CORS preflight requests correctly", async () => {
    const app = Fastify();
    await registerSecurityPlugins(app, { corsOrigins: ["https://example.com"] });
    app.post("/mcp", async () => ({ status: "ok" }));

    const res = await app.inject({
      method: "OPTIONS",
      url: "/mcp",
      headers: {
        origin: "https://example.com",
        "access-control-request-method": "POST",
      },
    });

    expect(res.statusCode).toBe(204);
    expect(res.headers["access-control-allow-origin"]).toBe("https://example.com");
    await app.close();
  });

  it("should enforce rate limiting and respond with 429", async () => {
    const app = Fastify();
    await registerSecurityPlugins(app, {
      rateLimitMax: 2,
      rateLimitTimeWindow: "1 minute",
    });
    app.get("/limited", async () => ({ message: "ok" }));

    const res1 = await app.inject({ method: "GET", url: "/limited" });
    expect(res1.statusCode).toBe(200);

    const res2 = await app.inject({ method: "GET", url: "/limited" });
    expect(res2.statusCode).toBe(200);

    const res3 = await app.inject({ method: "GET", url: "/limited" });
    expect(res3.statusCode).toBe(429);
    const body = JSON.parse(res3.body);
    expect(body.error).toBe("Too Many Requests");
    await app.close();
  });
});
