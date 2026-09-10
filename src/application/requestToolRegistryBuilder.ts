import type { CustomMcpUpstream, CustomUpstreamService } from "../api/customUpstreamService.js";
import type { AuthenticatedPrincipal } from "../auth/scopeGuard.js";
import type { UpstreamConfig } from "../config/upstreamConfig.js";
import { ResilientUpstreamConnection } from "../upstream/resilientUpstreamConnection.js";
import { RemoteMcpConnection } from "../upstream/remoteMcpConnection.js";
import { ToolRegistry } from "../upstream/toolRegistry.js";
import type { UpstreamConnection } from "../upstream/upstreamConnection.js";
import { validateSafeEndpointUrl } from "../policy/urlValidator.js";

export interface RequestLogger {
  warn(context: Record<string, unknown>, message: string): void;
  error(context: Record<string, unknown>, message: string): void;
}

export interface RequestToolRegistry {
  registry: ToolRegistry;
  activeCustomPrefixes: readonly string[];
  close(): Promise<void>;
}

type CustomUpstreamSource = Pick<CustomUpstreamService, "list" | "getDecryptedAuthValue">;
type ConnectionFactory = (
  config: UpstreamConfig,
  headers: Record<string, string>,
) => Promise<UpstreamConnection>;
type EndpointValidator = (endpointUrl: string) => Promise<void>;

const defaultConnectionFactory: ConnectionFactory = async (config, headers) => {
  const connection = await RemoteMcpConnection.connect(config, headers);
  return new ResilientUpstreamConnection(connection, {
    failureThreshold: 3,
    resetTimeoutMs: 15000,
  });
};

/**
 * Builds the per-request view of the tool registry. Static routes remain shared;
 * owner-scoped custom upstreams are connected only for their owner's request.
 */
export class RequestToolRegistryBuilder {
  constructor(
    private readonly baseRegistry: ToolRegistry,
    private readonly customUpstreams?: CustomUpstreamSource,
    private readonly connectionFactory: ConnectionFactory = defaultConnectionFactory,
    private readonly endpointValidator: EndpointValidator = validateSafeEndpointUrl,
  ) {}

  async build(
    principal: AuthenticatedPrincipal | undefined,
    logger: RequestLogger,
  ): Promise<RequestToolRegistry> {
    if (!principal || !this.customUpstreams) {
      return sharedRegistry(this.baseRegistry);
    }

    const upstreams = await this.customUpstreams.list(principal.userId);
    const enabled = upstreams.filter((upstream) => upstream.isEnabled);
    if (enabled.length === 0) {
      return sharedRegistry(this.baseRegistry);
    }

    const registry = this.baseRegistry.clone();
    const connections: UpstreamConnection[] = [];
    const activeCustomPrefixes: string[] = [];

    for (const upstream of enabled) {
      const connection = await this.addCustomUpstream(
        upstream,
        principal.userId,
        registry,
        logger,
      );
      if (connection) {
        connections.push(connection);
        activeCustomPrefixes.push(upstream.toolPrefix);
      }
    }

    return {
      registry,
      activeCustomPrefixes: Object.freeze(activeCustomPrefixes),
      close: async () => {
        await Promise.all(connections.map((connection) => connection.close()));
      },
    };
  }

  private async addCustomUpstream(
    upstream: CustomMcpUpstream,
    userId: string,
    registry: ToolRegistry,
    logger: RequestLogger,
  ): Promise<UpstreamConnection | undefined> {
    let connection: UpstreamConnection | undefined;
    try {
      // Validate again at connection time. Registration-time DNS results can
      // become stale before a user invokes their custom upstream.
      await this.endpointValidator(upstream.endpointUrl);
      const auth = await this.customUpstreams!.getDecryptedAuthValue(userId, upstream.toolPrefix);
      connection = await this.connectionFactory(
        {
          id: upstream.id,
          toolPrefix: upstream.toolPrefix,
          networkScope: "external",
          endpoint: upstream.endpointUrl,
          transport: "streamable-http",
          enabled: true,
          timeoutMs: 30000,
          headers: {},
        },
        authorizationHeaders(auth),
      );
      await registry.addRoute(connection);
      return connection;
    } catch (err) {
      await connection?.close();
      logger.error({ err, prefix: upstream.toolPrefix }, "Failed to connect custom upstream");
      return undefined;
    }
  }
}

function authorizationHeaders(auth: Awaited<ReturnType<CustomUpstreamSource["getDecryptedAuthValue"]>>): Record<string, string> {
  if (!auth?.authValue) return {};
  return {
    [auth.authHeaderName]: auth.authType === "bearer" && !auth.authValue.startsWith("Bearer ")
      ? `Bearer ${auth.authValue}`
      : auth.authValue,
  };
}

function sharedRegistry(registry: ToolRegistry): RequestToolRegistry {
  return {
    registry,
    activeCustomPrefixes: [],
    close: async () => undefined,
  };
}
