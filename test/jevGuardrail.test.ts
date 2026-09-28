import { describe, expect, it, vi } from "vitest";
import { loadJevConfig } from "../src/config/jev.js";
import { JevClient } from "../src/jev/jevClient.js";
import { JevGuardrail, JevGuardrailViolationError } from "../src/policy/jevGuardrail.js";

describe("Jev Guardrail & Client", () => {
  describe("loadJevConfig", () => {
    it("loads default configuration when env is empty", () => {
      const config = loadJevConfig({});
      expect(config.apiKey).toBeUndefined();
      expect(config.endpoint).toBe("https://api.typesafe.ai");
      expect(config.model).toBe("jev-latest");
      expect(config.timeoutMs).toBe(500);
      expect(config.guardrailEnabled).toBe(false); // disabled if apiKey is missing
      expect(config.routerEnabled).toBe(false);
      expect(config.riskThreshold).toBe(0.85);
    });

    it("enables guardrail when apiKey is provided", () => {
      const config = loadJevConfig({
        JEV_API_KEY: "test-api-key",
        JEV_TIMEOUT_MS: "300",
        JEV_RISK_THRESHOLD: "0.9",
      });
      expect(config.apiKey).toBe("test-api-key");
      expect(config.timeoutMs).toBe(300);
      expect(config.guardrailEnabled).toBe(true);
      expect(config.routerEnabled).toBe(true);
      expect(config.riskThreshold).toBe(0.9);
    });
  });

  it.each([
    { value: "true", enabled: true },
    { value: "TRUE", enabled: true },
    { value: "false", enabled: false },
  ])("respects explicit JEV flags ($value) with a configured key", ({ value, enabled }) => {
    const config = loadJevConfig({
      JEV_API_KEY: "test-api-key",
      JEV_GUARDRAIL_ENABLED: value,
      JEV_ROUTER_ENABLED: value,
    });
    expect(config.guardrailEnabled).toBe(enabled);
    expect(config.routerEnabled).toBe(enabled);
  });

  describe("JevClient", () => {
    it("throws error if API key is not configured", async () => {
      const client = new JevClient(loadJevConfig({}));
      await expect(
        client.decide({ query: "test" }, {}),
      ).rejects.toThrow("JEV_API_KEY is not configured");
    });
  });

  describe("JevGuardrail", () => {
    it("skips evaluation if client is not enabled", async () => {
      const client = new JevClient(loadJevConfig({}));
      const guardrail = new JevGuardrail(client);

      // Should not throw
      await expect(
        guardrail.validate("knowledge.search", { query: "hello" }),
      ).resolves.toBeUndefined();
    });

    it("allows execution when risk is below threshold", async () => {
      const client = new JevClient(loadJevConfig({ JEV_API_KEY: "dummy" }));
      vi.spyOn(client, "decide").mockResolvedValueOnce({
        model: "jev-latest",
        answers: {
          is_malicious: { type: "noul", noul: 0.05 },
        },
      });

      const guardrail = new JevGuardrail(client, { riskThreshold: 0.85 });
      await expect(
        guardrail.validate("knowledge.search", { query: "test safe query" }),
      ).resolves.toBeUndefined();
    });

    it("blocks execution when risk meets or exceeds threshold", async () => {
      const client = new JevClient(loadJevConfig({ JEV_API_KEY: "dummy" }));
      vi.spyOn(client, "decide").mockResolvedValueOnce({
        model: "jev-latest",
        answers: {
          is_malicious: { type: "noul", noul: 0.98 },
        },
      });

      const guardrail = new JevGuardrail(client, { riskThreshold: 0.85 });
      await expect(
        guardrail.validate("bash.execute", { command: "rm -rf /" }),
      ).rejects.toThrow(JevGuardrailViolationError);
    });

    it("fails open on API error when failOpen is true", async () => {
      const client = new JevClient(loadJevConfig({ JEV_API_KEY: "dummy" }));
      vi.spyOn(client, "decide").mockRejectedValueOnce(new Error("Network timeout"));

      const warnLog = vi.fn();
      const logger = { warn: warnLog, error: vi.fn() };

      const guardrail = new JevGuardrail(client, { failOpen: true });
      await expect(
        guardrail.validate("knowledge.search", { query: "test" }, logger),
      ).resolves.toBeUndefined();

      expect(warnLog).toHaveBeenCalled();
    });

    it("fails closed on API error when failOpen is false", async () => {
      const client = new JevClient(loadJevConfig({ JEV_API_KEY: "dummy" }));
      vi.spyOn(client, "decide").mockRejectedValueOnce(new Error("Network timeout"));

      const guardrail = new JevGuardrail(client, { failOpen: false });
      await expect(
        guardrail.validate("knowledge.search", { query: "test" }),
      ).rejects.toThrow("Network timeout");
    });

    it("safely truncates massive payload exceeding character limit", async () => {
      const client = new JevClient(loadJevConfig({ JEV_API_KEY: "dummy" }));
      const decideSpy = vi.spyOn(client, "decide").mockResolvedValueOnce({
        model: "jev-latest",
        answers: {
          is_malicious: { type: "noul", noul: 0.05 },
        },
      });

      const guardrail = new JevGuardrail(client);
      const massivePayload = "A".repeat(150_000);

      await guardrail.validate("knowledge.search", { bigData: massivePayload });
      expect(decideSpy).toHaveBeenCalledTimes(1);

      const firstCall = decideSpy.mock.calls[0];
      if (!firstCall) throw new Error("Expected Jev decide to be called");
      const passedState = firstCall[0] as { tool_name: string; arguments: string };
      expect(passedState.arguments.length).toBeLessThan(100_000);
      expect(passedState.arguments).toContain("[TRUNCATED_FOR_SAFETY]");
    });
  });
});
