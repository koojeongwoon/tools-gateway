/** Operator-configured, owner-bound CLI relay. Never selected by upstream tool annotations. */
import type { CallToolResult } from "@modelcontextprotocol/client";
import { OutboundSecretLeakGuard } from "./outboundSecretLeakGuard.js";

export const AGENT_TOOL_COMMANDS = new Set([
  "workspace", "search", "document_reader", "keywords", "wordpress", "thumbnail_tool",
  "auth_workspace", "auth_google_ads",
]);
const MAX_FILE = 8 * 1024 * 1024;
const MAX_TEXT = 2 * 1024 * 1024;
const namePattern = /^(?:input-[0-9]+(?:\.[a-zA-Z0-9]{1,10})?|state\.txt|output\.png)$/;
const secretGuard = new OutboundSecretLeakGuard();

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid agent-tools envelope");
  return value as Record<string, unknown>;
}
function exactKeys(value: Record<string, unknown>, allowed: string[]): void {
  if (Object.keys(value).some(key => !allowed.includes(key))) throw new Error("Invalid agent-tools fields");
}
function files(value: unknown): Record<string, Buffer> {
  const attachments = object(value ?? {});
  if (Object.keys(attachments).length > 6) throw new Error("Too many agent-tools attachments");
  const decoded: Record<string, Buffer> = {};
  let total = 0;
  for (const [name, encoded] of Object.entries(attachments)) {
    if (!namePattern.test(name) || typeof encoded !== "string" || encoded.length > Math.ceil(MAX_FILE / 3) * 4) {
      throw new Error("Invalid agent-tools attachment");
    }
    const data = Buffer.from(encoded, "base64");
    if (data.toString("base64") !== encoded || data.length > MAX_FILE) throw new Error("Invalid agent-tools encoding");
    total += data.length;
    decoded[name] = data;
  }
  if (total > 16 * 1024 * 1024) throw new Error("Agent-tools attachments exceed limit");
  return decoded;
}

export function validateAgentToolsArguments(command: string, args: Record<string, unknown>): void {
  if (!AGENT_TOOL_COMMANDS.has(command)) throw new Error("Unknown agent-tools command");
  exactKeys(args, ["argv", "files", "stdin"]);
  if (!Array.isArray(args.argv) || args.argv.length > 128 || args.argv.some(
    item => typeof item !== "string" || item.length > 65536 || item.includes("\0"),
  )) throw new Error("Invalid agent-tools argv");
  if (args.stdin !== undefined && (typeof args.stdin !== "string" || args.stdin.length > 8193)) {
    throw new Error("Invalid agent-tools stdin");
  }
  const consent = command === "auth_workspace" || command === "auth_google_ads";
  if (args.stdin && command !== "auth_google_ads") throw new Error("Unexpected agent-tools stdin");
  if (!consent) secretGuard.validate({ argv: args.argv });
  const decoded = files(args.files);
  for (const [name, data] of Object.entries(decoded)) {
    if (name === "output.png" || name === "state.txt" && !consent) throw new Error("Unexpected attachment");
    // Consent state is an intentional short-lived authorization handoff. File bytes are
    // transported as data, never interpreted as shell commands. Scan UTF-8 text for secrets.
    if (name !== "state.txt" && !data.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) {
      const text = data.toString("utf8");
      if (Buffer.from(text, "utf8").equals(data)) secretGuard.validate({ document: text });
    }
  }
}

export function validateAgentToolsResult(command: string, raw: CallToolResult): CallToolResult {
  if (raw.isError) throw new Error("Agent-tools rejected execution; inspect status before retrying");
  const texts = (raw.content ?? []).filter(block => block.type === "text");
  if (texts.length !== 1 || texts[0]!.type !== "text" || texts[0]!.text.length > 24 * 1024 * 1024) {
    throw new Error("Invalid agent-tools result");
  }
  const data = object(JSON.parse(texts[0]!.text));
  if (raw.structuredContent && JSON.stringify(raw.structuredContent) !== JSON.stringify(data)) {
    throw new Error("Inconsistent agent-tools result");
  }
  exactKeys(data, ["exit_code", "stdout", "stderr", "files"]);
  if (!Number.isInteger(data.exit_code) || (data.exit_code as number) < 0 || (data.exit_code as number) > 255
      || typeof data.stdout !== "string" || typeof data.stderr !== "string"
      || data.stdout.length > MAX_TEXT || data.stderr.length > MAX_TEXT) throw new Error("Invalid agent-tools result fields");
  for (const name of Object.keys(files(data.files))) {
    if (!(name === "output.png" && command === "thumbnail_tool")
        && !(name === "state.txt" && command.startsWith("auth_"))) throw new Error("Unexpected output attachment");
  }
  // Keep file bytes, IDs, consent state and user-requested content intact. The configured
  // owner-bound service is responsible for credential isolation; audit never records bodies.
  return raw;
}
