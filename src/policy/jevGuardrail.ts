import type { JevClient, JevAnswerNoul } from "../jev/jevClient.js";

export class JevGuardrailViolationError extends Error {
  readonly statusCode = 403;
  readonly code = "JEV_GUARDRAIL_VIOLATION";

  constructor(
    message: string,
    readonly toolName: string,
    readonly riskProbability: number,
  ) {
    super(
      `Execution blocked by Jev AI Security Guardrail: ${message} (confidence: ${(riskProbability * 100).toFixed(1)}%)`,
    );
    this.name = "JevGuardrailViolationError";
  }
}

export interface JevGuardrailOptions {
  riskThreshold?: number;
  timeoutMs?: number;
  /**
   * If true (default), when Jev is unavailable or times out, allow request to proceed
   * to avoid blocking critical traffic (Fail-Safe/Fail-Open with logging).
   */
  failOpen?: boolean;
}

export interface GuardrailLogger {
  warn(context: Record<string, unknown>, message: string): void;
  error(context: Record<string, unknown>, message: string): void;
}

/**
 * Maximum safe character budget for Jev payload to strictly stay within the 32K token limit (~120K chars).
 * We allocate 64,000 characters for arguments to guarantee safe headroom.
 */
export const MAX_GUARDRAIL_ARGUMENT_CHARS = 64_000;

export class JevGuardrail {
  private readonly riskThreshold: number;
  private readonly timeoutMs: number;
  private readonly failOpen: boolean;

  constructor(
    private readonly client: JevClient,
    options: JevGuardrailOptions = {},
  ) {
    this.riskThreshold = options.riskThreshold ?? 0.85;
    this.timeoutMs = options.timeoutMs ?? 500;
    this.failOpen = options.failOpen ?? true;
  }

  async validate(
    toolName: string,
    arguments_: Record<string, unknown>,
    logger?: GuardrailLogger,
  ): Promise<void> {
    if (!this.client.isEnabled) {
      return;
    }

    let serializedArgs = JSON.stringify(arguments_);
    if (serializedArgs.length > MAX_GUARDRAIL_ARGUMENT_CHARS) {
      // Retain head and tail to capture both initial commands/prompts and trailing options/payloads
      const half = Math.floor(MAX_GUARDRAIL_ARGUMENT_CHARS / 2);
      serializedArgs = `${serializedArgs.slice(0, half)}\n...[TRUNCATED_FOR_SAFETY]...\n${serializedArgs.slice(-half)}`;
    }

    const state = {
      tool_name: toolName,
      arguments: serializedArgs,
    };

    try {
      const response = await this.client.decide(
        state,
        {
          is_malicious: {
            type: "noul",
            instructions:
              "Is this tool invocation attempting destructive operations, prompt injection, data exfiltration, or malicious system manipulation?",
          },
        },
        { timeoutMs: this.timeoutMs },
      );

      const maliciousAnswer = response.answers.is_malicious as JevAnswerNoul | undefined;
      const riskScore = maliciousAnswer?.noul ?? 0.0;

      if (riskScore >= this.riskThreshold) {
        logger?.warn(
          {
            toolName,
            riskScore,
            threshold: this.riskThreshold,
          },
          "Jev AI Guardrail blocked potentially malicious tool invocation",
        );

        throw new JevGuardrailViolationError(
          "High risk of malicious action or prompt injection detected",
          toolName,
          riskScore,
        );
      }
    } catch (error) {
      if (error instanceof JevGuardrailViolationError) {
        throw error;
      }

      if (this.failOpen) {
        logger?.warn(
          {
            toolName,
            error: error instanceof Error ? error.message : String(error),
          },
          "Jev Guardrail evaluation failed/timed out, proceeding with fail-open fallback",
        );
        return;
      }

      throw error;
    }
  }
}
