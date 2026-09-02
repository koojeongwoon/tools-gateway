import { describe, expect, it, vi, beforeEach } from "vitest";
import { CircuitBreaker, CircuitBreakerOpenError } from "../src/resilience/circuitBreaker.js";

describe("CircuitBreaker", () => {
  let breaker: CircuitBreaker;

  beforeEach(() => {
    breaker = new CircuitBreaker("test-service", {
      failureThreshold: 3,
      resetTimeoutMs: 100,
      halfOpenMaxCalls: 1,
    });
  });

  it("starts in CLOSED state and executes successful calls normally", async () => {
    expect(breaker.getState()).toBe("CLOSED");
    const result = await breaker.execute(async () => "success");
    expect(result).toBe("success");
    expect(breaker.getState()).toBe("CLOSED");
  });

  it("transitions to OPEN state when failure threshold is reached", async () => {
    const failingFn = vi.fn().mockRejectedValue(new Error("upstream failure"));

    for (let i = 0; i < 2; i++) {
      await expect(breaker.execute(failingFn)).rejects.toThrow("upstream failure");
      expect(breaker.getState()).toBe("CLOSED");
    }

    // 3번째 실패: threshold 도달
    await expect(breaker.execute(failingFn)).rejects.toThrow("upstream failure");
    expect(breaker.getState()).toBe("OPEN");
  });

  it("fails fast in OPEN state with CircuitBreakerOpenError without calling wrapped function", async () => {
    const failingFn = vi.fn().mockRejectedValue(new Error("upstream failure"));
    for (let i = 0; i < 3; i++) {
      await expect(breaker.execute(failingFn)).rejects.toThrow();
    }
    expect(breaker.getState()).toBe("OPEN");

    const targetFn = vi.fn().mockResolvedValue("should not run");
    await expect(breaker.execute(targetFn)).rejects.toBeInstanceOf(CircuitBreakerOpenError);
    expect(targetFn).not.toHaveBeenCalled();
  });

  it("transitions to HALF_OPEN after resetTimeoutMs and resets to CLOSED on success", async () => {
    const failingFn = vi.fn().mockRejectedValue(new Error("upstream failure"));
    for (let i = 0; i < 3; i++) {
      await expect(breaker.execute(failingFn)).rejects.toThrow();
    }
    expect(breaker.getState()).toBe("OPEN");

    // Wait for resetTimeoutMs (100ms)
    await new Promise((resolve) => setTimeout(resolve, 120));

    // Next call should transition to HALF_OPEN and succeed
    const successFn = vi.fn().mockResolvedValue("recovered");
    const result = await breaker.execute(successFn);
    expect(result).toBe("recovered");
    expect(breaker.getState()).toBe("CLOSED");
    expect(breaker.getStats().consecutiveFailures).toBe(0);
  });

  it("transitions back to OPEN if HALF_OPEN probe call fails", async () => {
    const failingFn = vi.fn().mockRejectedValue(new Error("upstream failure"));
    for (let i = 0; i < 3; i++) {
      await expect(breaker.execute(failingFn)).rejects.toThrow();
    }
    expect(breaker.getState()).toBe("OPEN");

    await new Promise((resolve) => setTimeout(resolve, 120));

    // HALF_OPEN probe call fails
    await expect(breaker.execute(failingFn)).rejects.toThrow("upstream failure");
    expect(breaker.getState()).toBe("OPEN");
  });
});
