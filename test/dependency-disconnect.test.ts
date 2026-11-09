import { afterEach, expect, it, vi } from "vitest";
import { createDatabasePool } from "../src/config/database.js";
import { createRedisClient } from "../src/config/redis.js";

afterEach(() => vi.restoreAllMocks());

it("survives idle PostgreSQL errors without logging connection details", async () => {
  const warning = vi.spyOn(console, "warn").mockImplementation(() => {});
  const pool = createDatabasePool({ enabled: true, pool: {} })!;
  try {
    expect(() => pool.emit("error", new Error("fixture-only connection details"))).not.toThrow();
    expect(warning).toHaveBeenCalled();
    expect(JSON.stringify(warning.mock.calls)).not.toContain("fixture-only");
  } finally {
    await pool.end();
  }
});

it("handles disconnect errors on every independent Redis consumer connection", () => {
  const warning = vi.spyOn(console, "warn").mockImplementation(() => {});
  for (const role of ["cache", "sync", "lifecycle", "service-access"]) {
    const client = createRedisClient({ socket: { host: "127.0.0.1", port: 1 }, password: "fixture-only" });
    expect(() => client.emit("error", new Error(`fixture-only ${role}`))).not.toThrow();
  }
  expect(warning).toHaveBeenCalledTimes(4);
  expect(JSON.stringify(warning.mock.calls)).not.toContain("fixture-only");
});
