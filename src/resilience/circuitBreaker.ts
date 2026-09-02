export type CircuitBreakerState = "CLOSED" | "OPEN" | "HALF_OPEN";

export interface CircuitBreakerOptions {
  failureThreshold?: number;
  resetTimeoutMs?: number;
  halfOpenMaxCalls?: number;
}

export interface CircuitBreakerStats {
  readonly state: CircuitBreakerState;
  readonly consecutiveFailures: number;
  readonly lastFailureTime: number | null;
  readonly totalSuccesses: number;
  readonly totalFailures: number;
  readonly totalShortCircuited: number;
}

export class CircuitBreakerOpenError extends Error {
  readonly statusCode: number = 503;
  readonly name: string = "CircuitBreakerOpenError";

  constructor(readonly serviceName: string, readonly retryAfterMs: number) {
    super(`Circuit breaker is OPEN for upstream service '${serviceName}'. Fast-failing request. Retry after ${Math.ceil(retryAfterMs / 1000)}s.`);
  }
}

export class CircuitBreaker {
  private state: CircuitBreakerState = "CLOSED";
  private consecutiveFailures = 0;
  private lastFailureTime: number | null = null;
  private halfOpenCalls = 0;
  private totalSuccesses = 0;
  private totalFailures = 0;
  private totalShortCircuited = 0;

  private readonly failureThreshold: number;
  private readonly resetTimeoutMs: number;
  private readonly halfOpenMaxCalls: number;

  constructor(
    readonly serviceName: string,
    options?: CircuitBreakerOptions,
  ) {
    this.failureThreshold = Math.max(1, options?.failureThreshold ?? 5);
    this.resetTimeoutMs = Math.max(10, options?.resetTimeoutMs ?? 30000);
    this.halfOpenMaxCalls = Math.max(1, options?.halfOpenMaxCalls ?? 1);
  }

  getState(): CircuitBreakerState {
    this.evaluateState();
    return this.state;
  }

  getStats(): CircuitBreakerStats {
    this.evaluateState();
    return Object.freeze({
      state: this.state,
      consecutiveFailures: this.consecutiveFailures,
      lastFailureTime: this.lastFailureTime,
      totalSuccesses: this.totalSuccesses,
      totalFailures: this.totalFailures,
      totalShortCircuited: this.totalShortCircuited,
    });
  }

  private evaluateState(): void {
    if (this.state === "OPEN" && this.lastFailureTime !== null) {
      const elapsed = Date.now() - this.lastFailureTime;
      if (elapsed >= this.resetTimeoutMs) {
        this.state = "HALF_OPEN";
        this.halfOpenCalls = 0;
      }
    }
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    this.evaluateState();

    if (this.state === "OPEN") {
      this.totalShortCircuited++;
      const retryAfterMs = this.lastFailureTime !== null
        ? Math.max(0, this.resetTimeoutMs - (Date.now() - this.lastFailureTime))
        : this.resetTimeoutMs;
      throw new CircuitBreakerOpenError(this.serviceName, retryAfterMs);
    }

    if (this.state === "HALF_OPEN") {
      if (this.halfOpenCalls >= this.halfOpenMaxCalls) {
        this.totalShortCircuited++;
        throw new CircuitBreakerOpenError(this.serviceName, this.resetTimeoutMs);
      }
      this.halfOpenCalls++;
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  private onSuccess(): void {
    this.totalSuccesses++;
    this.consecutiveFailures = 0;
    this.halfOpenCalls = 0;
    this.state = "CLOSED";
  }

  private onFailure(): void {
    this.totalFailures++;
    this.consecutiveFailures++;
    this.lastFailureTime = Date.now();

    if (this.state === "HALF_OPEN" || this.consecutiveFailures >= this.failureThreshold) {
      this.state = "OPEN";
    }
  }

  reset(): void {
    this.state = "CLOSED";
    this.consecutiveFailures = 0;
    this.lastFailureTime = null;
    this.halfOpenCalls = 0;
  }
}
