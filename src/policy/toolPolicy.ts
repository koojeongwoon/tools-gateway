export type ToolPolicyConfig = {
  default: "deny";
  allow: string[];
  deny: string[];
};

export class ToolPolicy {
  private readonly allowed: RegExp[];
  private readonly denied: RegExp[];

  constructor(config: ToolPolicyConfig) {
    this.allowed = config.allow.map(toPattern);
    this.denied = config.deny.map(toPattern);
  }

  allows(toolName: string): boolean {
    if (this.denied.some((pattern) => pattern.test(toolName))) {
      return false;
    }
    return this.allowed.some((pattern) => pattern.test(toolName));
  }

  async enforce<T>(toolName: string, operation: () => Promise<T>): Promise<T> {
    if (!this.allows(toolName)) {
      throw new Error(`tool is not allowed by gateway policy: ${toolName}`);
    }
    return operation();
  }
}

function toPattern(glob: string): RegExp {
  const escaped = glob.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${escaped.replaceAll("*", ".*")}$`);
}
