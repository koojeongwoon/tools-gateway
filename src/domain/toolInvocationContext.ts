import {
  type AuditLogger,
  calculateCredits,
  estimateTokens,
} from "../audit/auditLogger.js";

export interface GatewayRequestContext {
  readonly requestId?: string | undefined;
  readonly userId?: string | undefined;
  readonly apiKeyId?: string | undefined;
  readonly ipAddress?: string | undefined;
  readonly userAgent?: string | undefined;
}

export interface ToolInvocationOptions {
  readonly requestContext?: GatewayRequestContext | undefined;
  readonly auditLogger?: AuditLogger | undefined;
}

export class ToolInvocationContext {
  readonly requestContext: GatewayRequestContext | undefined;
  private readonly auditLogger: AuditLogger | undefined;

  constructor(options?: ToolInvocationOptions) {
    this.requestContext = options?.requestContext;
    this.auditLogger = options?.auditLogger;
  }

  async invoke<T>(
    toolName: string,
    arguments_: Record<string, unknown>,
    operation: () => Promise<T>,
  ): Promise<T> {
    const start = performance.now();
    const requestId = this.requestContext?.requestId;
    const userId = this.requestContext?.userId ?? "anonymous";
    const apiKeyId = this.requestContext?.apiKeyId;
    const ipAddress = this.requestContext?.ipAddress;
    const userAgent = this.requestContext?.userAgent;

    const argsJson = JSON.stringify(arguments_);
    const requestBytes = Buffer.byteLength(argsJson, "utf8");
    const inputTokens = estimateTokens(argsJson);

    try {
      const result = await operation();
      const durationMs = performance.now() - start;

      if (this.auditLogger && this.requestContext?.userId) {
        const isError = (result as any)?.isError === true;
        const resultJson = JSON.stringify(result ?? {});
        const responseBytes = Buffer.byteLength(resultJson, "utf8");
        const outputTokens = estimateTokens(resultJson);
        const creditsUsed = calculateCredits(toolName, requestBytes, responseBytes);

        void this.auditLogger.log({
          requestId,
          userId,
          apiKeyId,
          toolName,
          status: isError ? "ERROR" : "SUCCESS",
          statusCode: isError ? 500 : 200,
          durationMs,
          requestBytes,
          responseBytes,
          inputTokens,
          outputTokens,
          creditsUsed,
          arguments: arguments_,
          ipAddress,
          userAgent,
        });
      }

      return result;
    } catch (error) {
      const durationMs = performance.now() - start;
      if (this.auditLogger && this.requestContext?.userId) {
        const isForbidden =
          (error as any)?.statusCode === 403 ||
          (error instanceof Error &&
            (error.message.includes("outside API key scope") ||
              error.message.includes("not allowed by gateway policy")));
        const errorJson = JSON.stringify({ error: String(error) });
        const responseBytes = Buffer.byteLength(errorJson, "utf8");
        const outputTokens = estimateTokens(errorJson);
        const creditsUsed = calculateCredits(toolName, requestBytes, responseBytes);

        void this.auditLogger.log({
          requestId,
          userId,
          apiKeyId,
          toolName,
          status: isForbidden ? "FORBIDDEN" : "ERROR",
          statusCode: isForbidden ? 403 : 500,
          durationMs,
          requestBytes,
          responseBytes,
          inputTokens,
          outputTokens,
          creditsUsed,
          arguments: arguments_,
          ipAddress,
          userAgent,
        });
      }
      throw error;
    }
  }
}
