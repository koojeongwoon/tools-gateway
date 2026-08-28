import type { Tool } from "@modelcontextprotocol/server";

export interface AuthenticatedPrincipal {
  userId: string;
  apiKeyId: string;
  systemRole: string;
  scopes: string[];
  permissions: Record<string, string[]>;
}

export class ScopeGuard {
  constructor(private readonly principal: AuthenticatedPrincipal) {}

  allows(tool: Pick<Tool, "name" | "annotations">): boolean {
    const separator = tool.name.indexOf(".");
    if (separator < 1) return false;
    const service = tool.name.slice(0, separator);
    const action = tool.annotations?.readOnlyHint === true ? "read" : "write";
    const permitted = this.principal.permissions[service] ?? [];
    if (!permitted.includes(action) && !permitted.includes("admin")) return false;

    return this.principal.scopes.some(
      (scope) =>
        scope === "*" ||
        scope === `${service}:*` ||
        scope === `${service}:${action}`,
    );
  }
}
