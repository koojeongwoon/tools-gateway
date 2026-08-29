import { describe, expect, it } from "vitest";
import { loadDatabaseConfig } from "../src/config/database.js";
import { migrations } from "../src/database/migrations.js";

describe("database configuration", () => {
  it("is disabled by default", () => {
    expect(loadDatabaseConfig({})).toEqual({ enabled: false });
  });

  it("requires every credential field when enabled", () => {
    expect(() => loadDatabaseConfig({ DATABASE_ENABLED: "true" })).toThrow(
      "PGHOST",
    );
  });

  it("builds a bounded PostgreSQL pool without logging a connection URL", () => {
    const config = loadDatabaseConfig({
      DATABASE_ENABLED: "true",
      PGHOST: "postgres-service.infra.svc.cluster.local",
      PGDATABASE: "tools_gateway_db",
      PGUSER: "tools_gateway_user",
      PGPASSWORD: "test-secret",
      PGPOOL_MAX: "4",
    });

    expect(config).toMatchObject({
      enabled: true,
      pool: {
        host: "postgres-service.infra.svc.cluster.local",
        database: "tools_gateway_db",
        user: "tools_gateway_user",
        password: "test-secret",
        max: 4,
      },
    });
  });
});

describe("database migrations", () => {
  it("defines the five SaaS tables and security indexes", () => {
    const sql = migrations.map(({ sql }) => sql).join("\n");

    for (const table of [
      "users",
      "user_service_permissions",
      "api_keys",
      "user_mcp_upstreams",
      "tool_usage_logs",
      "user_tool_permissions",
    ]) {
      expect(sql).toContain(`CREATE TABLE ${table}`);
    }
    expect(sql).toContain("key_hash VARCHAR(64) UNIQUE NOT NULL");
    expect(sql).toContain("ip_address INET");
  });
});
