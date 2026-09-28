import type { JevConfig } from "../config/jev.js";

export interface JevQuestionNoul {
  type: "noul";
  instructions?: string;
  criteria?: {
    true?: string;
    false?: string;
  };
}

export interface JevQuestionChoice {
  type: "choice";
  instructions?: string;
  criteria: Record<string, string | null>;
}

export interface JevQuestionScore {
  type: "score";
  instructions?: string;
  criteria: string[];
}

export type JevQuestion = JevQuestionNoul | JevQuestionChoice | JevQuestionScore;

export interface JevAnswerNoul {
  type: "noul";
  noul: number; // calibrated probability 0.0 - 1.0
}

export interface JevAnswerChoice {
  type: "choice";
  choice: string;
  probabilities?: Record<string, number>;
}

export interface JevAnswerScore {
  type: "score";
  score: number;
  expected_score?: number;
}

export type JevAnswer = JevAnswerNoul | JevAnswerChoice | JevAnswerScore;

export interface JevSystemOneResponse {
  model: string;
  answers: Record<string, JevAnswer>;
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
  };
}

export class JevClient {
  constructor(private readonly config: JevConfig) {}

  get isEnabled(): boolean {
    return Boolean(this.config.apiKey);
  }

  async decide(
    state: Record<string, unknown>,
    questions: Record<string, JevQuestion>,
    options?: { timeoutMs?: number; model?: string },
  ): Promise<JevSystemOneResponse> {
    if (!this.config.apiKey) {
      throw new Error("JEV_API_KEY is not configured");
    }

    const timeoutMs = options?.timeoutMs ?? this.config.timeoutMs;
    const model = options?.model ?? this.config.model;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const url = `${this.config.endpoint}/v1/systemone`;
      const response = await fetch(url, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.config.apiKey}`,
          "Content-Type": "application/json",
          "User-Agent": "tools-gateway/jev-client",
        },
        body: JSON.stringify({
          model,
          state,
          questions,
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => "");
        throw new Error(
          `Jev API returned HTTP ${response.status}: ${errorText.slice(0, 200)}`,
        );
      }

      return (await response.json()) as JevSystemOneResponse;
    } finally {
      clearTimeout(timer);
    }
  }
}
