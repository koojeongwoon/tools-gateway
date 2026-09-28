import type { CallToolResult, Tool } from "@modelcontextprotocol/client";
import type { JevClient, JevAnswerChoice, JevAnswerNoul } from "./jevClient.js";

export interface TargetToolCandidate {
  publicName: string;
  description?: string;
}

export interface RouterLogger {
  info?(context: Record<string, unknown>, message: string): void;
  warn(context: Record<string, unknown>, message: string): void;
  error(context: Record<string, unknown>, message: string): void;
}

export interface JevVirtualRouterOptions {
  timeoutMs?: number;
}

export interface RouteDecision {
  selectedTool: string;
  confidence: number;
  reason?: string;
}

export const MAX_ROUTER_INTENT_CHARS = 16_000;
export const MAX_TOOL_DESCRIPTION_CHARS = 500;
export const MAX_CANDIDATE_TOOLS = 100;

export class JevVirtualRouter {
  private readonly timeoutMs: number;

  constructor(
    private readonly client: JevClient,
    options: JevVirtualRouterOptions = {},
  ) {
    this.timeoutMs = options.timeoutMs ?? 1000;
  }

  /**
   * Generates the schema definition for the virtual meta-dispatcher tool.
   */
  getVirtualToolDefinition(): Tool {
    return {
      name: "gateway.smart_dispatch",
      description:
        "Intelligent meta-router powered by Jev. Automatically selects and invokes the best matching backend tool based on user intent and parameters.",
      inputSchema: {
        type: "object",
        properties: {
          intent: {
            type: "string",
            description: "Natural language description or instruction of the task to perform.",
          },
          parameters: {
            type: "object",
            description: "Arguments or payload to pass to the selected target tool.",
          },
        },
        required: ["intent"],
      },
    };
  }

  /**
   * Dispatches the user intent to the most appropriate tool candidate using Jev choice questions.
   */
  async route(
    intent: string,
    candidates: readonly TargetToolCandidate[],
    logger?: RouterLogger,
  ): Promise<RouteDecision> {
    const firstCandidate = candidates[0];
    if (!firstCandidate) {
      throw new Error("No available tools to route to");
    }

    if (candidates.length === 1) {
      return {
        selectedTool: firstCandidate.publicName,
        confidence: 1.0,
        reason: "Single candidate available",
      };
    }

    // Cap candidate count and trim descriptions to safely fit well within the 32K token budget
    const safeCandidates = candidates.slice(0, MAX_CANDIDATE_TOOLS);
    const safeIntent = intent.slice(0, MAX_ROUTER_INTENT_CHARS);

    // Build choice criteria for Jev
    const criteria: Record<string, string> = {};
    for (const candidate of safeCandidates) {
      const desc = candidate.description
        ? candidate.description.slice(0, MAX_TOOL_DESCRIPTION_CHARS)
        : `Tool ${candidate.publicName}`;
      criteria[candidate.publicName] = desc;
    }

    const state = {
      user_intent: safeIntent,
      candidates: safeCandidates.map((c) => ({
        name: c.publicName,
        description: c.description ? c.description.slice(0, MAX_TOOL_DESCRIPTION_CHARS) : undefined,
      })),
    };

    try {
      const response = await this.client.decide(
        state,
        {
          selected_tool: {
            type: "choice",
            instructions: "Which tool is best suited to fulfill the user's intent?",
            criteria,
          },
        },
        { timeoutMs: this.timeoutMs },
      );

      const choiceAnswer = response.answers.selected_tool as JevAnswerChoice | undefined;
      const selected = choiceAnswer?.choice;

      if (!selected || !criteria[selected]) {
        // Fallback to first candidate if Jev returned unknown choice
        return {
          selectedTool: firstCandidate.publicName,
          confidence: 0.0,
          reason: "Jev returned invalid choice, fallback to default",
        };
      }

      const confidence = choiceAnswer?.probabilities?.[selected] ?? 0.9;
      return {
        selectedTool: selected,
        confidence,
      };
    } catch (error) {
      logger?.warn(
        {
          intent,
          error: error instanceof Error ? error.message : String(error),
        },
        "Jev tool routing failed, falling back to first available tool",
      );

      return {
        selectedTool: firstCandidate.publicName,
        confidence: 0.0,
        reason: "Jev routing error fallback",
      };
    }
  }
}
