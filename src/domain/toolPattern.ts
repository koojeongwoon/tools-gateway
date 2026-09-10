/** Shared, fail-closed grammar for public Gateway tool patterns. */
export function validateToolPattern(pattern: string): void {
  if (typeof pattern !== "string" || pattern.trim().length === 0) {
    throw new Error("Tool policy pattern must be a non-empty string");
  }
  if (/[\r\n\0]/.test(pattern)) {
    throw new Error(`Invalid characters in tool policy pattern: ${JSON.stringify(pattern)}`);
  }
}

export function compileToolPattern(pattern: string): RegExp {
  validateToolPattern(pattern);
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^${escaped.replaceAll("*", ".*")}$`);
}

export function matchesToolPattern(pattern: string, toolName: string): boolean {
  validateToolPattern(pattern);
  return compileToolPattern(pattern).test(toolName);
}
