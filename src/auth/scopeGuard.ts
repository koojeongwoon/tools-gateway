export interface AuthenticatedPrincipal {
  userId: string;
  apiKeyId: string;
  systemRole: string;
  scopes: string[];
  toolPatterns: string[];
}

export class ScopeGuard {
  constructor(private readonly principal: AuthenticatedPrincipal) {}

  allows(toolName: string): boolean {
    return this.principal.toolPatterns.some((pattern) => matchesToolPattern(pattern, toolName)) &&
      this.principal.scopes.some((scope) =>
        scope.startsWith("tool:") && matchesToolPattern(scope.slice(5), toolName),
      );
  }
}

export function matchesToolPattern(pattern: string, toolName: string): boolean {
  return pattern.endsWith("*")
    ? toolName.startsWith(pattern.slice(0, -1))
    : pattern === toolName;
}
