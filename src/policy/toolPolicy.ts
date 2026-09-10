export type ToolPolicyConfig = {
  default: "deny";
  allow: string[];
  deny: string[];
};

export class ToolPolicy {
  private readonly allowed: RegExp[];
  private readonly denied: RegExp[];

  constructor(config: ToolPolicyConfig) {
    this.allowed = config.allow.map(compileToolPattern);
    this.denied = config.deny.map(compileToolPattern);
  }

  allows(toolName: string): boolean {
    if (this.denied.some((pattern) => pattern.test(toolName))) {
      return false;
    }
    return this.allowed.some((pattern) => pattern.test(toolName));
  }

  allowPattern(glob: string): void {
    this.allowed.push(compileToolPattern(glob));
  }

  async enforce<T>(toolName: string, operation: () => Promise<T>): Promise<T> {
    if (!this.allows(toolName)) {
      throw new Error(`tool is not allowed by gateway policy: ${toolName}`);
    }
    return operation();
  }
}
import { compileToolPattern } from "../domain/toolPattern.js";
