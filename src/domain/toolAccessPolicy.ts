import type { AuthenticatedPrincipal } from "../auth/scopeGuard.js";
import type { ToolPolicyConfig } from "../policy/toolPolicy.js";
import { compileToolPattern, matchesToolPattern } from "./toolPattern.js";

export interface ToolAccessPolicyOptions {
  globalConfig: ToolPolicyConfig;
  principal?: AuthenticatedPrincipal | undefined;
}

export class ToolAccessPolicy {
  private readonly allowedPatterns: readonly RegExp[];
  private readonly deniedPatterns: readonly RegExp[];
  private readonly allowedGlobs: readonly string[];
  private readonly deniedGlobs: readonly string[];
  private readonly principal: AuthenticatedPrincipal | undefined;

  constructor(options: ToolAccessPolicyOptions) {
    this.allowedGlobs = Object.freeze([...options.globalConfig.allow]);
    this.deniedGlobs = Object.freeze([...options.globalConfig.deny]);
    this.allowedPatterns = Object.freeze(this.allowedGlobs.map(compileToolPattern));
    this.deniedPatterns = Object.freeze(this.deniedGlobs.map(compileToolPattern));
    this.principal = options.principal;
  }

  allows(toolName: string): boolean {
    // 1. 글로벌 거부(Deny) 규칙 먼저 검사
    if (this.deniedPatterns.some((pattern) => pattern.test(toolName))) {
      return false;
    }

    // 2. 글로벌 허용(Allow) 규칙 검사
    const globallyAllowed = this.allowedPatterns.some((pattern) => pattern.test(toolName));
    if (!globallyAllowed) {
      return false;
    }

    // 3. Principal이 존재할 경우 스코프 및 패턴 검사
    if (this.principal) {
      const matchesPrincipalPattern = this.principal.toolPatterns.some((pattern) =>
        matchesToolPattern(pattern, toolName),
      );
      const matchesPrincipalScope = this.principal.scopes.some((scope) =>
        scope.startsWith("tool:") && matchesToolPattern(scope.slice(5), toolName),
      );
      return matchesPrincipalPattern && matchesPrincipalScope;
    }

    return true;
  }

  assertAllowed(toolName: string): void {
    if (!this.allows(toolName)) {
      const err = new Error(`tool is not allowed by gateway policy: ${toolName}`);
      (err as any).statusCode = 403;
      throw err;
    }
  }

  withAllowedPattern(glob: string): ToolAccessPolicy {
    return new ToolAccessPolicy({
      globalConfig: {
        default: "deny",
        allow: [...this.allowedGlobs, glob],
        deny: [...this.deniedGlobs],
      },
      principal: this.principal,
    });
  }
}
