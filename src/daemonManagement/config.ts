import { loadMcpOAuthConfig } from "../auth/mcpOAuthVerifier.js";
export interface ManagementConfig {
  issuer: string; tenant: string; resource: string; client: string;
  readerClient: string; readerSecret: string;
}
export function loadManagementConfig(env: NodeJS.ProcessEnv = process.env): ManagementConfig | undefined {
  if (env.DAEMON_MANAGEMENT_ENABLED !== "true") return undefined;
  const mcp = loadMcpOAuthConfig(env);
  const resource = env.DAEMON_MANAGEMENT_RESOURCE ?? "https://tools-gateway.lynply.com/api/v1/daemon-management";
  for (const [value, path] of [[mcp.issuer, `/t/${mcp.tenantId}`], [resource, "/api/v1/daemon-management"]]) {
    const u = new URL(value!);
    if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash || u.pathname !== path || u.href !== value) {
      throw new Error("Invalid daemon management HTTPS configuration");
    }
  }
  if (!env.DAEMON_DEVICE_READER_SECRET) throw new Error("Daemon management requires IAM device reader credentials");
  return { issuer: mcp.issuer, tenant: mcp.tenantId, resource, client: "tools-daemon-management",
    readerClient: "tools-gateway-device-reader", readerSecret: env.DAEMON_DEVICE_READER_SECRET };
}
